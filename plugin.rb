# frozen_string_literal: true
# name: discourse-digest-eligibility-rules
# about: Configurable eligibility + exclusion condition-groups (OR of AND rules) to decide who receives digest emails, incl. PG emails_list checks + optional L1/L2 caching.
# version: 2.9.0
# authors: you
# required_version: 3.0.0
# v2.9.0:
# - NEW: digest_eligibility_custom_query_recent_digest_failsafe — removes users
#   from custom query results who already have a digest_attempted_at within the
#   last N hours, preventing double-sends within a configurable window.
# - NEW: digest_eligibility_custom_query_recent_digest_hours — the lookback
#   window in hours (default 23).
# v2.8.0:
# - NEW: Custom base query mode (digest_eligibility_custom_query_mode).
#   When enabled, the plugin replaces Discourse's built-in target_user_ids SQL
#   with a user-supplied SELECT query. All existing include/exclude rule logic
#   still runs on top of the returned IDs (unless apply_rules is off).
# - NEW: digest_eligibility_custom_query_sql — the replacement query (must
#   return a column named `user_id` or `id`).
# - NEW: digest_eligibility_custom_query_failsafe — when enabled (default true),
#   IDs from the custom query are joined back against Discourse's digest-eligibility
#   conditions so users with digest disabled / suspended / not activated are never
#   sent to the queue even if your query returns them.
# - NEW: digest_eligibility_custom_query_apply_rules — when enabled (default true),
#   the include/exclude rule groups still run on top of the custom query results.
#   Disable to use the custom query output (after failsafe) without any further filtering.
# v2.6.2:
# - FIX: stop relying on enqueue_for_user for stats counting (it is not hit in this Discourse flow).
# - Stats are now recorded from execute, based on the filtered target_user_ids captured during the run.
# - Keeps detailed debug logs for target_user_ids + execute flow.
# - Adds per-run de-dup guard so stats are bumped once per user_id per job execution.
# - Keeps existing include/exclude logic unchanged.

enabled_site_setting :digest_eligibility_rules_enabled

after_initialize do
  require "json"
  require "time"
  require "set"

  module ::DigestEligibilityRules
    PLUGIN_NAME = "discourse-digest-eligibility-rules"
    STORE_KEY_PREFIX = "u:" # PluginStore key => "u:<user_id>"

    # --------------------------------
    # Logging (WARN so it shows in /admin/logs)
    # --------------------------------
    def self.debug_enabled?
      SiteSetting.digest_eligibility_rules_debug
    rescue
      false
    end

    def self.debug(msg)
      return unless debug_enabled?
      Rails.logger.warn("[#{PLUGIN_NAME}] DEBUG #{msg}")
    rescue
    end

    def self.warn(msg)
      Rails.logger.warn("[#{PLUGIN_NAME}] #{msg}")
    rescue
    end

    # --------------------------------
    # GLOBAL OFF SWITCH
    # --------------------------------
    def self.globally_off?
      v = ENV["DIGEST_ELIGIBILITY_GLOBAL_OFF"].to_s.strip
      v == "1" || v.downcase == "true"
    rescue
      false
    end

    def self.enabled?
      return false if globally_off?
      SiteSetting.digest_eligibility_rules_enabled
    rescue
      false
    end

    def self.runtime_state_string
      "enabled=#{enabled?} site_setting=#{(SiteSetting.digest_eligibility_rules_enabled rescue 'ERR')} global_off=#{globally_off?} env_global_off=#{ENV['DIGEST_ELIGIBILITY_GLOBAL_OFF'].inspect}"
    rescue => e
      "runtime_state_error=#{e.class}: #{e.message}"
    end

    # --------------------------------
    # Switches for enabling include/exclude logic
    # --------------------------------
    def self.apply_includes?
      SiteSetting.digest_eligibility_rules_apply_includes
    rescue
      true
    end

    def self.apply_excludes?
      SiteSetting.digest_eligibility_rules_apply_excludes
    rescue
      true
    end

    # --------------------------------
    # Switch for how to mark skipped users' digest_attempted_at
    # --------------------------------
    def self.skipped_attempted_mode
      v = SiteSetting.digest_eligibility_rules_skipped_attempted_mode.to_s.strip.downcase
      v = "random_future" if v.blank?
      return v if %w[now random_future].include?(v)
      "random_future"
    rescue
      "random_future"
    end

    # --------------------------------
    # Custom base query mode
    # --------------------------------
    def self.custom_query_mode?
      SiteSetting.digest_eligibility_custom_query_mode
    rescue
      false
    end

    def self.custom_query_failsafe?
      SiteSetting.digest_eligibility_custom_query_failsafe
    rescue
      true
    end

    def self.custom_query_apply_rules?
      SiteSetting.digest_eligibility_custom_query_apply_rules
    rescue
      true
    end

    def self.custom_query_recent_digest_failsafe?
      SiteSetting.digest_eligibility_custom_query_recent_digest_failsafe
    rescue
      true
    end

    def self.custom_query_recent_digest_hours
      v = SiteSetting.digest_eligibility_custom_query_recent_digest_hours.to_i
      v = 23 if v <= 0
      v
    rescue
      23
    end

    def self.custom_query_recent_emailed_failsafe?
      SiteSetting.digest_eligibility_custom_query_recent_emailed_failsafe
    rescue
      false
    end

    def self.custom_query_recent_emailed_hours
      v = SiteSetting.digest_eligibility_custom_query_recent_emailed_hours.to_i
      v = 23 if v <= 0
      v
    rescue
      23
    end

    # Remove IDs that already have a digest_attempted_at within the last N hours.
    def self.apply_recent_digest_failsafe_filter(user_ids)
      return [] if user_ids.blank?

      hours = custom_query_recent_digest_hours
      recently_mailed = UserStat
        .where(user_id: user_ids)
        .where("digest_attempted_at > CURRENT_TIMESTAMP - (:hours * INTERVAL '1 hour')", hours: hours)
        .pluck(:user_id)

      recently_mailed_set = recently_mailed.to_set
      result = user_ids.reject { |id| recently_mailed_set.include?(id) }

      warn("apply_recent_digest_failsafe_filter: input=#{user_ids.length} removed=#{recently_mailed.length} (digest_attempted_at within last #{hours}h) passed=#{result.length}")
      result
    rescue => e
      warn("apply_recent_digest_failsafe_filter failed: #{e.class}: #{e.message}")
      []
    end

    # Remove IDs whose last_emailed_at is within the last N hours.
    def self.apply_recent_emailed_failsafe_filter(user_ids)
      return [] if user_ids.blank?

      hours = custom_query_recent_emailed_hours
      recently_mailed = User
        .where(id: user_ids)
        .where("last_emailed_at > CURRENT_TIMESTAMP - (:hours * INTERVAL '1 hour')", hours: hours)
        .pluck(:id)

      recently_mailed_set = recently_mailed.to_set
      result = user_ids.reject { |id| recently_mailed_set.include?(id) }

      warn("apply_recent_emailed_failsafe_filter: input=#{user_ids.length} removed=#{recently_mailed.length} (last_emailed_at within last #{hours}h) passed=#{result.length}")
      result
    rescue => e
      warn("apply_recent_emailed_failsafe_filter failed: #{e.class}: #{e.message}")
      []
    end

    # Run the user-supplied SQL and return an array of integer user IDs.
    # Accepts a column named `user_id` or `id` (first match wins per row).
    def self.run_custom_base_query
      sql = SiteSetting.digest_eligibility_custom_query_sql.to_s.strip

      if sql.blank?
        warn("custom_query: no SQL configured — returning empty set")
        return []
      end

      unless sql_list_query_safe?(sql)
        warn("custom_query REJECTED: query failed safety check (must be SELECT, no write statements)")
        return []
      end

      res = ::DB.query(sql)

      ary =
        if res.is_a?(Array)
          res
        elsif res.respond_to?(:to_a)
          tmp = res.to_a
          tmp.is_a?(Array) ? tmp : []
        else
          []
        end

      out = []
      ary.each do |r|
        v =
          if r.respond_to?(:[])
            (r[:user_id] rescue nil) ||
              (r[:id]      rescue nil) ||
              (r["user_id"] rescue nil) ||
              (r["id"]      rescue nil)
          elsif r.respond_to?(:user_id)
            (r.user_id rescue nil)
          elsif r.respond_to?(:id)
            (r.id rescue nil)
          end

        next if v.nil?
        i = v.to_i
        out << i if i > 0
      end

      result = out.uniq
      warn("custom_query: returned #{result.length} user IDs")
      result
    rescue => e
      warn("custom_query failed: #{e.class}: #{e.message}\n#{e.backtrace&.first(5)&.join("\n")}")
      []
    end

    # Re-filter IDs through Discourse's standard digest-eligibility conditions.
    # Guarantees users with digest disabled, suspended accounts, or zero-frequency
    # settings are never queued even if the custom query returns them.
    def self.apply_digest_failsafe_filter(user_ids)
      return [] if user_ids.blank?

      ids =
        User
          .real
          .activated
          .not_staged
          .not_suspended
          .joins(:user_option, :user_stat, :user_emails)
          .where(id: user_ids)
          .where("user_options.email_digests")
          .where(
            "COALESCE(user_options.digest_after_minutes, ?) > 0",
            SiteSetting.default_email_digest_frequency,
          )
          .where("user_stats.bounce_score < ?", SiteSetting.bounce_score_threshold)
          .where("user_emails.primary")
          .pluck(:id)

      debug("apply_digest_failsafe_filter: input=#{user_ids.length} passed=#{ids.length} removed=#{user_ids.length - ids.length}")
      ids
    rescue => e
      warn("apply_digest_failsafe_filter failed: #{e.class}: #{e.message}")
      # On error, fail safe: return empty so nothing unexpected is queued
      []
    end

    # --------------------------------
    # Stats (PluginStore - informational only)
    # --------------------------------
    def self.stats_key(user_id)
      "#{STORE_KEY_PREFIX}#{user_id}"
    end

    def self.fetch_stats_map(user_ids)
      return {} if user_ids.blank?

      keys = user_ids.map { |id| stats_key(id) }
      rows =
        PluginStoreRow
          .where(plugin_name: PLUGIN_NAME, key: keys)
          .pluck(:key, :value)

      out = {}
      rows.each do |k, v|
        begin
          out[k] = JSON.parse(v.to_s)
        rescue
          out[k] = {}
        end
      end
      out
    rescue => e
      warn("fetch_stats_map failed: #{e.class}: #{e.message}")
      {}
    end

    def self.stats_for_user(stats_map, user_id)
      stats_map[stats_key(user_id)] || {}
    end

    def self.bump_stats!(user_id, now_utc)
      key = stats_key(user_id)
      raw = PluginStore.get(PLUGIN_NAME, key)
      data = {}

      begin
        data = JSON.parse(raw.to_s) if raw.present?
      rescue
        data = {}
      end

      cnt = (data["digest_count"].to_i rescue 0) + 1
      data["digest_count"] = cnt
      data["last_digest_at_utc"] = now_utc.utc.iso8601

      PluginStore.set(PLUGIN_NAME, key, data.to_json)

      verify_raw = PluginStore.get(PLUGIN_NAME, key)
      debug("bump_stats! user_id=#{user_id} key=#{key} old_raw=#{raw.inspect} new_data=#{data.inspect} verify_raw=#{verify_raw.inspect}")
      data
    rescue => e
      warn("bump_stats failed user_id=#{user_id}: #{e.class}: #{e.message}")
      nil
    end

    def self.bump_stats_for_users!(user_ids, now_utc)
      ids = Array(user_ids).map(&:to_i).uniq
      return 0 if ids.empty?

      cnt = 0
      ids.each do |uid|
        data = bump_stats!(uid, now_utc)
        cnt += 1 if data.present?
      end
      cnt
    rescue => e
      warn("bump_stats_for_users failed: #{e.class}: #{e.message}")
      0
    end

    # --------------------------------
    # Rules JSON parsing
    # --------------------------------
    def self.load_json_array_setting(setting_name)
      raw = SiteSetting.public_send(setting_name).to_s.strip
      return [] if raw.blank?
      parsed = JSON.parse(raw)
      return [] unless parsed.is_a?(Array)
      parsed.select { |g| g.is_a?(Hash) }
    rescue => e
      warn("ERROR parsing #{setting_name}: #{e.class}: #{e.message}")
      []
    end

    def self.load_eligible_groups
      load_json_array_setting(:digest_eligibility_rules_groups_json)
    end

    def self.load_exclude_groups
      load_json_array_setting(:digest_eligibility_rules_excludes_json)
    end

    # --------------------------------
    # Helpers
    # --------------------------------
    IDENT_RE = /\A[a-zA-Z_][a-zA-Z0-9_]*\z/

    def self.valid_ident?(s)
      s.present? && s.to_s.match?(IDENT_RE)
    end

    def self.normalize_email(email)
      email.to_s.strip.downcase
    end

    def self.email_domain_of(email)
      normalize_email(email).split("@", 2)[1].to_s
    end

    def self.parse_time_utc(s)
      return nil if s.blank?
      Time.parse(s.to_s).utc
    rescue
      nil
    end

    def self.safe_int(v, default = 0)
      Integer(v)
    rescue
      default
    end

    # --------------------------------
    # Reason counters
    # --------------------------------
    def self.rc_inc!(rc, key, n = 1)
      return if rc.nil?
      rc[key] = (rc[key].to_i + n.to_i)
    rescue
    end

    def self.rc_merge_missing!(rc, miss_hash)
      return if rc.nil? || miss_hash.nil?
      miss_hash.each { |k, v| rc_inc!(rc, :"missing_emails_list:#{k}", v.to_i) }
    rescue
    end

    def self.rc_summary_string(rc)
      return "" if rc.nil? || rc.empty?
      pairs = rc.sort_by { |k, v| [-v.to_i, k.to_s] }
      pairs.map { |k, v| "#{k}=#{v}" }.join(" ")
    rescue
      ""
    end

    # --------------------------------
    # Mark skipped users as "attempted" to avoid re-candidacy churn
    # --------------------------------
    def self.mark_digest_attempted_for_users!(user_ids, now_utc, rc: nil)
      ids = Array(user_ids).map(&:to_i).uniq
      return 0 if ids.empty?

      total = 0
      batch_size = 5_000

      quoted_now =
        begin
          ActiveRecord::Base.connection.quote(now_utc)
        rescue
          "'#{now_utc.utc.iso8601}'"
        end

      mode = skipped_attempted_mode

      attempted_expr =
        if mode == "now"
          Arel.sql("(#{quoted_now}::timestamptz)")
        else
          Arel.sql("(#{quoted_now}::timestamptz + (random() * interval '6 days 20 hours'))")
        end

      ids.each_slice(batch_size) do |slice|
        begin
          n = UserStat.where(user_id: slice).update_all(digest_attempted_at: attempted_expr)
          total += (n.to_i rescue slice.length)
        rescue => e
          warn("mark_digest_attempted failed batch size=#{slice.length}: #{e.class}: #{e.message}")
        end
      end

      rc_inc!(rc, :marked_digest_attempted_at_rows, total) if rc
      rc_inc!(rc, :"marked_digest_attempted_at_mode:#{mode}", total) if rc
      total
    rescue => e
      warn("mark_digest_attempted failed: #{e.class}: #{e.message}")
      0
    end

    # --------------------------------
    # Watched category map (bulk)
    # --------------------------------
    def self.fetch_watched_category_map(user_ids, all_needed_category_ids)
      return {} if user_ids.blank? || all_needed_category_ids.blank?

      levels = CategoryUser.watching_levels
      rows =
        CategoryUser
          .where(user_id: user_ids, category_id: all_needed_category_ids, notification_level: levels)
          .pluck(:user_id, :category_id)

      map = Hash.new { |h, k| h[k] = Set.new }
      rows.each { |uid, cid| map[uid] << cid.to_i }
      map
    rescue => e
      warn("fetch_watched_category_map failed: #{e.class}: #{e.message}")
      {}
    end

    # --------------------------------
    # Watched min-count
    # --------------------------------
    def self.check_watched_min_count!(group, watched_set)
      obj = group["requires_watched_category_ids_min_count"]
      return true unless obj.is_a?(Hash)

      ids = obj["category_ids"]
      min = obj["min_count"]
      return false unless ids.is_a?(Array)

      want = ids.map(&:to_i).uniq
      minc = safe_int(min, 0)
      minc = 0 if minc < 0

      return true if want.empty? || minc <= 0
      return false if watched_set.nil?

      cnt = 0
      want.each do |cid|
        if watched_set.include?(cid)
          cnt += 1
          return true if cnt >= minc
        end
      end
      false
    rescue
      false
    end

    # --------------------------------
    # emails_list caching controls
    # --------------------------------
    def self.l1_enabled?
      SiteSetting.digest_eligibility_emails_list_l1_cache_enabled
    rescue
      true
    end

    def self.l2_enabled?
      SiteSetting.digest_eligibility_emails_list_l2_cache_enabled
    rescue
      true
    end

    def self.emails_list_cache_ttl_seconds
      v = (SiteSetting.digest_eligibility_emails_list_cache_ttl_seconds || 900).to_i
      v = 0 if v < 0
      v
    rescue
      900
    end

    def self.emails_list_cache_ttl_jitter_seconds
      v = (SiteSetting.digest_eligibility_emails_list_cache_ttl_jitter_seconds || 0).to_i
      v = 0 if v < 0
      v
    rescue
      0
    end

    def self.emails_list_page_size
      v = (SiteSetting.digest_eligibility_emails_list_page_size || 50_000).to_i
      v = 50_000 if v <= 0
      v
    rescue
      50_000
    end

    def self.emails_list_max_rows
      v = (SiteSetting.digest_eligibility_emails_list_max_rows || 0).to_i
      v = 0 if v < 0
      v
    rescue
      0
    end

    def self.discourse_cache_prefix
      p = SiteSetting.digest_eligibility_emails_list_cache_prefix.to_s.strip
      p = "der:emails_list:v1" if p.blank?
      p
    rescue
      "der:emails_list:v1"
    end

    def self.l2_cache_key(table_name, column_name)
      "#{discourse_cache_prefix}:public.#{table_name}.#{column_name}"
    end

    def self.l1_cache_key(table_name, column_name)
      "public.#{table_name}.#{column_name}"
    end

    def self.l1_cache
      @l1_cache ||= {}
    end

    def self.effective_ttl_seconds
      ttl = emails_list_cache_ttl_seconds.to_i
      return 0 if ttl <= 0
      j = emails_list_cache_ttl_jitter_seconds.to_i
      j = 0 if j < 0
      ttl + (j > 0 ? rand(0..j) : 0)
    rescue
      emails_list_cache_ttl_seconds.to_i
    end

    def self.load_emails_lists_config
      raw = SiteSetting.digest_eligibility_emails_lists_json.to_s.strip
      return {} if raw.blank?

      parsed = JSON.parse(raw)
      return {} unless parsed.is_a?(Array)

      out = {}
      parsed.each do |row|
        next unless row.is_a?(Hash)

        name = row["name"].to_s.strip
        t    = row["table"].to_s.strip
        c    = row["column"].to_s.strip
        c = "email" if c.blank?

        next unless valid_ident?(name) && valid_ident?(t) && valid_ident?(c)
        out[name] = { table: t, column: c }
      end
      out
    rescue => e
      warn("ERROR parsing digest_eligibility_emails_lists_json: #{e.class}: #{e.message}")
      {}
    end

    def self.load_all_emails_array_from_pg(table_name, column_name)
      t = table_name.to_s.strip
      c = column_name.to_s.strip
      c = "email" if c.blank?

      table_ref = %Q{"public"."#{t}"}
      col_ref   = %Q{"#{c}"}

      out = []
      offset = 0
      psize = emails_list_page_size
      mrows = emails_list_max_rows

      loop do
        sql = <<~SQL
          SELECT lower(#{col_ref}) AS email
          FROM #{table_ref}
          ORDER BY lower(#{col_ref})
          LIMIT #{psize} OFFSET #{offset}
        SQL

        res = ::DB.query(sql)

        ary =
          if res.is_a?(Array)
            res
          elsif res.respond_to?(:to_a)
            tmp = res.to_a
            tmp.is_a?(Array) ? tmp : []
          else
            []
          end

        break if ary.empty?

        ary.each do |r|
          v =
            if r.respond_to?(:[])
              (r[:email] rescue nil) || (r["email"] rescue nil)
            elsif r.respond_to?(:email)
              (r.email rescue nil)
            end
          s = v.to_s.strip.downcase
          out << s unless s.empty?
        end

        offset += psize
        break if mrows > 0 && out.length >= mrows
      end

      out.uniq!
      out = out.take(mrows) if mrows > 0 && out.length > mrows
      out
    rescue => e
      warn("emails_list query failed table=public.#{table_name} col=#{column_name}: #{e.class}: #{e.message}")
      []
    end

    def self.fetch_all_emails_from_pg_list(table_name, column_name)
      t = table_name.to_s.strip
      c = column_name.to_s.strip
      c = "email" if c.blank?

      unless valid_ident?(t) && valid_ident?(c)
        warn("emails_list invalid identifiers table=#{t.inspect} col=#{c.inspect} (must match #{IDENT_RE})")
        return Set.new
      end

      ttl = effective_ttl_seconds
      now = Time.now.to_i

      l1k = l1_cache_key(t, c)
      if l1_enabled? && ttl > 0
        cached = l1_cache[l1k]
        if cached && cached[:expires_at].to_i > now
          debug("emails_list L1 HIT key=#{l1k} rows=#{(cached[:emails] || []).length}")
          return Set.new(cached[:emails] || [])
        end
      end

      arr = nil
      if l2_enabled? && ttl > 0
        l2k = l2_cache_key(t, c)
        begin
          arr =
            Discourse.cache.fetch(l2k, expires_in: ttl.seconds) do
              debug("emails_list L2 MISS key=#{l2k} => loading from PG public.#{t}.#{c}")
              load_all_emails_array_from_pg(t, c)
            end

          arr = [] unless arr.is_a?(Array)
          arr = arr.map { |x| x.to_s.strip.downcase }.reject(&:blank?).uniq
          debug("emails_list L2 HIT/MISS-RETURN key=#{l2k} rows=#{arr.length}")
        rescue => e
          debug("emails_list L2 fetch failed key=#{l2k}: #{e.class}: #{e.message}")
          arr = nil
        end
      end

      arr ||= load_all_emails_array_from_pg(t, c)

      if l1_enabled? && ttl > 0
        l1_cache[l1k] = { expires_at: now + ttl, emails: arr }
        debug("emails_list L1 STORE key=#{l1k} rows=#{arr.length} ttl=#{ttl}")
      end

      Set.new(arr)
    end

    # --------------------------------
    # User field requirements (by field *name*)
    # --------------------------------
    def self.collect_user_field_names_from_group(g, out)
      return unless g.is_a?(Hash)

      %w[requires_user_field_equals_any requires_user_field_equals_all].each do |k|
        next unless g[k].is_a?(Array)
        g[k].each do |clause|
          next unless clause.is_a?(Hash)
          fname = clause["field"].to_s.strip
          out << fname unless fname.blank?
        end
      end

      collect_user_field_names_from_group(g["exclude"], out) if g["exclude"].is_a?(Hash)
    end

    def self.collect_user_field_names(groups)
      out = []
      Array(groups).each { |g| collect_user_field_names_from_group(g, out) }
      out.map(&:to_s).map(&:strip).reject(&:blank?).uniq
    end

    def self.fetch_user_field_ids_by_name(field_names)
      names = Array(field_names).map { |x| x.to_s.strip }.reject(&:blank?).uniq
      return {} if names.empty?
      UserField.where(name: names).pluck(:name, :id).to_h
    rescue => e
      warn("fetch_user_field_ids_by_name failed: #{e.class}: #{e.message}")
      {}
    end

    def self.fetch_user_custom_fields_map(user_ids, field_ids_by_name)
      return {} if user_ids.blank? || field_ids_by_name.blank?

      wanted = field_ids_by_name.map { |name, id| ["user_field_#{id}", name] }.to_h
      keys = wanted.keys
      return {} if keys.empty?

      rows =
        UserCustomField
          .where(user_id: user_ids, name: keys)
          .pluck(:user_id, :name, :value)

      out = Hash.new { |h, k| h[k] = {} }
      rows.each do |uid, key, val|
        fname = wanted[key]
        next if fname.blank?
        out[uid][fname] = val.to_s
      end
      out
    rescue => e
      warn("fetch_user_custom_fields_map failed: #{e.class}: #{e.message}")
      {}
    end

    def self.check_user_field_clause_any!(clauses, user_field_values_by_name, rc: nil, context: nil)
      return true unless clauses.is_a?(Array) && clauses.present?

      clauses.each do |clause|
        next unless clause.is_a?(Hash)
        fname  = clause["field"].to_s.strip
        values = clause["values"]
        next if fname.blank? || !values.is_a?(Array)

        have = user_field_values_by_name[fname].to_s
        want = values.map { |x| x.to_s }.reject(&:blank?)
        next if want.empty?

        if want.include?(have)
          rc_inc!(rc, :"#{context || 'group'}:user_field_any_matched") if rc
          return true
        end
      end

      rc_inc!(rc, :"#{context || 'group'}:user_field_any_failed") if rc
      false
    rescue
      false
    end

    def self.check_user_field_clause_all!(clauses, user_field_values_by_name, rc: nil, context: nil)
      return true unless clauses.is_a?(Array) && clauses.present?

      clauses.each do |clause|
        next unless clause.is_a?(Hash)
        fname  = clause["field"].to_s.strip
        values = clause["values"]
        return false if fname.blank? || !values.is_a?(Array)

        have = user_field_values_by_name[fname].to_s
        want = values.map { |x| x.to_s }.reject(&:blank?)
        return false if want.empty?

        unless want.include?(have)
          rc_inc!(rc, :"#{context || 'group'}:user_field_all_failed") if rc
          return false
        end
      end

      rc_inc!(rc, :"#{context || 'group'}:user_field_all_matched") if rc
      true
    rescue
      false
    end

    # --------------------------------
    # Collect emails_list names referenced by groups (including nested exclude)
    # --------------------------------
    def self.collect_emails_list_names_from_group(g, out)
      return unless g.is_a?(Hash)

      %w[
        requires_email_in_emails_lists_any
        requires_email_in_emails_lists_all
        requires_email_not_in_emails_lists_any
      ].each do |k|
        next unless g[k].is_a?(Array)
        g[k].each do |name|
          s = name.to_s.strip
          out << s unless s.blank?
        end
      end

      collect_emails_list_names_from_group(g["exclude"], out) if g["exclude"].is_a?(Hash)
    end

    def self.collect_emails_list_names(groups)
      out = []
      Array(groups).each { |g| collect_emails_list_names_from_group(g, out) }
      out.map(&:to_s).map(&:strip).reject(&:blank?).uniq
    end

    def self.precompute_emails_lists_by_name(referenced_names, config_map)
      out = {}
      names = Array(referenced_names).map { |x| x.to_s.strip }.reject(&:blank?).uniq
      return out if names.empty?

      names.each do |name|
        cfg = config_map[name]
        if !cfg || cfg[:table].blank? || cfg[:column].blank?
          out[name] = nil
          debug("emails_list precompute name=#{name} MISSING/INVALID config")
          next
        end

        out[name] = fetch_all_emails_from_pg_list(cfg[:table], cfg[:column])
        debug("emails_list loaded name=#{name} table=public.#{cfg[:table]} col=#{cfg[:column]} rows=#{out[name].length}")
      end

      out
    end

    def self.group_references_missing_emails_list?(names, lists_by_name)
      names.any? { |n| !lists_by_name.key?(n) || lists_by_name[n].nil? }
    end

    def self.find_missing_emails_list_refs_in_groups(groups, emails_lists_by_name)
      out = Hash.new(0)
      Array(groups).each do |g|
        next unless g.is_a?(Hash)
        names = []
        collect_emails_list_names_from_group(g, names)
        names.each do |n|
          s = n.to_s.strip
          next if s.blank?
          if !emails_lists_by_name.key?(s) || emails_lists_by_name[s].nil?
            out[s] += 1
          end
        end
      end
      out
    rescue
      {}
    end

    # --------------------------------
    # Group evaluation
    # --------------------------------
    def self.user_matches_group?(group, user_id:, email_domain:, watched_set:, stats:, now_utc:, email_norm:, emails_lists_by_name:, user_fields_by_name:, rc: nil, context: nil)
      if group["exclude"].is_a?(Hash)
        if user_matches_group?(group["exclude"],
                               user_id: user_id,
                               email_domain: email_domain,
                               watched_set: watched_set,
                               stats: stats,
                               now_utc: now_utc,
                               email_norm: email_norm,
                               emails_lists_by_name: emails_lists_by_name,
                               user_fields_by_name: user_fields_by_name,
                               rc: rc,
                               context: "nested_exclude")
          rc_inc!(rc, :"#{context || 'group'}:blocked_by_nested_exclude")
          return false
        end
      end

      if group["requires_user_field_equals_any"].is_a?(Array)
        ok = check_user_field_clause_any!(group["requires_user_field_equals_any"], user_fields_by_name, rc: rc, context: context || "group")
        return false unless ok
      end

      if group["requires_user_field_equals_all"].is_a?(Array)
        ok = check_user_field_clause_all!(group["requires_user_field_equals_all"], user_fields_by_name, rc: rc, context: context || "group")
        return false unless ok
      end

      if group["email_domain_in"].is_a?(Array)
        allowed = group["email_domain_in"].map { |x| x.to_s.downcase.strip }.reject(&:blank?).uniq
        if allowed.present? && !allowed.include?(email_domain)
          rc_inc!(rc, :"#{context || 'group'}:domain_not_allowed")
          return false
        end
      end

      if group["email_domain_not_in"].is_a?(Array)
        blocked = group["email_domain_not_in"].map { |x| x.to_s.downcase.strip }.reject(&:blank?).uniq
        if blocked.present? && blocked.include?(email_domain)
          rc_inc!(rc, :"#{context || 'group'}:domain_blocked")
          return false
        end
      end

      if group["requires_watched_category_ids_any"].is_a?(Array)
        req = group["requires_watched_category_ids_any"].map(&:to_i).uniq
        if req.present? && (watched_set.nil? || (watched_set & req).empty?)
          rc_inc!(rc, :"#{context || 'group'}:watched_any_failed")
          return false
        end
      end

      if group["requires_watched_category_ids_all"].is_a?(Array)
        req = group["requires_watched_category_ids_all"].map(&:to_i).uniq
        if req.present?
          if watched_set.nil?
            rc_inc!(rc, :"#{context || 'group'}:watched_all_failed_nil")
            return false
          end
          req.each do |cid|
            unless watched_set.include?(cid)
              rc_inc!(rc, :"#{context || 'group'}:watched_all_failed")
              return false
            end
          end
        end
      end

      unless check_watched_min_count!(group, watched_set)
        rc_inc!(rc, :"#{context || 'group'}:watched_min_count_failed")
        return false
      end

      digest_count = stats["digest_count"].to_i rescue 0
      last_at = parse_time_utc(stats["last_digest_at_utc"])

      if group.key?("max_digest_count")
        maxc = group["max_digest_count"].to_i
        if maxc >= 0 && digest_count > maxc
          rc_inc!(rc, :"#{context || 'group'}:max_digest_count_failed")
          return false
        end
      end

      if group.key?("min_days_since_last_digest")
        mind = group["min_days_since_last_digest"].to_i
        if last_at
          days = (now_utc - last_at) / 86400.0
          if days < mind
            rc_inc!(rc, :"#{context || 'group'}:min_days_since_failed")
            return false
          end
        end
      end

      if group.key?("max_days_since_last_digest")
        maxd = group["max_days_since_last_digest"].to_i
        unless last_at
          rc_inc!(rc, :"#{context || 'group'}:max_days_since_failed_no_last")
          return false
        end
        days = (now_utc - last_at) / 86400.0
        if days > maxd
          rc_inc!(rc, :"#{context || 'group'}:max_days_since_failed")
          return false
        end
      end

      if group["requires_email_in_emails_lists_any"].is_a?(Array)
        names = group["requires_email_in_emails_lists_any"].map { |x| x.to_s.strip }.reject(&:blank?).uniq
        if names.present?
          if group_references_missing_emails_list?(names, emails_lists_by_name)
            rc_inc!(rc, :"#{context || 'group'}:emails_list_missing_config_any")
            return false
          end
          ok = names.any? { |n| emails_lists_by_name[n].include?(email_norm) }
          unless ok
            rc_inc!(rc, :"#{context || 'group'}:emails_list_any_failed")
            return false
          end
        end
      end

      if group["requires_email_in_emails_lists_all"].is_a?(Array)
        names = group["requires_email_in_emails_lists_all"].map { |x| x.to_s.strip }.reject(&:blank?).uniq
        if names.present?
          if group_references_missing_emails_list?(names, emails_lists_by_name)
            rc_inc!(rc, :"#{context || 'group'}:emails_list_missing_config_all")
            return false
          end
          names.each do |n|
            unless emails_lists_by_name[n].include?(email_norm)
              rc_inc!(rc, :"#{context || 'group'}:emails_list_all_failed")
              return false
            end
          end
        end
      end

      if group["requires_email_not_in_emails_lists_any"].is_a?(Array)
        names = group["requires_email_not_in_emails_lists_any"].map { |x| x.to_s.strip }.reject(&:blank?).uniq
        if names.present?
          if group_references_missing_emails_list?(names, emails_lists_by_name)
            rc_inc!(rc, :"#{context || 'group'}:emails_list_missing_config_not_any")
            return false
          end
          blocked = names.any? { |n| emails_lists_by_name[n].include?(email_norm) }
          if blocked
            rc_inc!(rc, :"#{context || 'group'}:emails_list_not_any_failed")
            return false
          end
        end
      end

      rc_inc!(rc, :"#{context || 'group'}:matched")
      true
    end

    def self.user_matches_any_group?(groups, rc: nil, context: nil, **kwargs)
      groups.each do |g|
        next unless g.is_a?(Hash)
        if user_matches_group?(g, **kwargs, rc: rc, context: context)
          return true
        end
      end
      false
    end

    # --------------------------------
    # SQL-query-based email lists
    # --------------------------------

    SQL_LIST_CACHE_PREFIX = "der:sql_list:v1"

    # Basic safety check: query must look like a SELECT and must not contain
    # obvious write statements. Not a full SQL parser — just a sanity guard.
    def self.sql_list_query_safe?(query)
      q = query.to_s.strip
      return false if q.empty?
      normalized = q.gsub(/\A(\s|--[^\n]*\n|\/\*.*?\*\/)+/m, "").strip.upcase
      return false unless normalized.start_with?("SELECT")
      return false if normalized.match?(/\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE|EXECUTE|CALL)\b/)
      true
    rescue
      false
    end

    def self.load_sql_lists_config
      raw = SiteSetting.digest_eligibility_sql_lists_json.to_s.strip
      return {} if raw.blank?

      parsed = JSON.parse(raw)
      return {} unless parsed.is_a?(Array)

      out = {}
      parsed.each do |row|
        next unless row.is_a?(Hash)
        name  = row["name"].to_s.strip
        query = row["query"].to_s.strip
        ttl   = row["ttl_seconds"].to_i

        next if name.blank? || query.blank?
        next unless valid_ident?(name)

        unless sql_list_query_safe?(query)
          warn("sql_list name=#{name} REJECTED: query failed safety check")
          next
        end

        out[name] = { query: query, ttl_seconds: ttl }
      end
      out
    rescue => e
      warn("ERROR parsing digest_eligibility_sql_lists_json: #{e.class}: #{e.message}")
      {}
    end

    def self.sql_list_cache_key(name, query)
      digest = Digest::SHA1.hexdigest(query.to_s)[0, 16]
      "#{SQL_LIST_CACHE_PREFIX}:#{name}:#{digest}"
    end

    def self.fetch_emails_from_sql_list(name, query, ttl_seconds)
      ttl = ttl_seconds.to_i
      ttl = emails_list_cache_ttl_seconds if ttl <= 0

      cache_key = sql_list_cache_key(name, query)

      if l2_enabled? && ttl > 0
        begin
          arr = Discourse.cache.fetch(cache_key, expires_in: ttl.seconds) do
            debug("sql_list L2 MISS name=#{name} key=#{cache_key} => running query")
            run_sql_list_query(name, query)
          end
          arr = [] unless arr.is_a?(Array)
          arr = arr.map { |x| x.to_s.strip.downcase }.reject(&:blank?).uniq
          debug("sql_list L2 HIT/MISS-RETURN name=#{name} rows=#{arr.length}")
          return Set.new(arr)
        rescue => e
          debug("sql_list L2 fetch failed name=#{name}: #{e.class}: #{e.message}")
        end
      end

      arr = run_sql_list_query(name, query)
      Set.new(arr)
    rescue => e
      warn("fetch_emails_from_sql_list failed name=#{name}: #{e.class}: #{e.message}")
      Set.new
    end

    def self.run_sql_list_query(name, query)
      res = ::DB.query(query.to_s)

      ary =
        if res.is_a?(Array)
          res
        elsif res.respond_to?(:to_a)
          tmp = res.to_a
          tmp.is_a?(Array) ? tmp : []
        else
          []
        end

      out = []
      ary.each do |r|
        v =
          if r.respond_to?(:[])
            (r[:email] rescue nil) || (r["email"] rescue nil)
          elsif r.respond_to?(:email)
            (r.email rescue nil)
          end
        s = v.to_s.strip.downcase
        out << s unless s.empty?
      end

      out.uniq!
      debug("sql_list query name=#{name} returned rows=#{out.length}")
      out
    rescue => e
      warn("sql_list query failed name=#{name}: #{e.class}: #{e.message}")
      []
    end

    def self.precompute_sql_lists_by_name(referenced_names, sql_config)
      out = {}
      names = Array(referenced_names).map { |x| x.to_s.strip }.reject(&:blank?).uniq
      return out if names.empty?

      names.each do |name|
        cfg = sql_config[name]
        next unless cfg  # not a sql list, skip (may be a static list)

        out[name] = fetch_emails_from_sql_list(name, cfg[:query], cfg[:ttl_seconds])
        debug("sql_list loaded name=#{name} rows=#{out[name].length}")
      end

      out
    rescue => e
      warn("precompute_sql_lists_by_name failed: #{e.class}: #{e.message}")
      {}
    end

    # --------------------------------
    # Main filter
    # --------------------------------
    def self.filter_ids_by_rules(base_user_ids)
      return base_user_ids if base_user_ids.blank?

      eligible_groups = load_eligible_groups
      exclude_groups  = load_exclude_groups
      now_utc = Time.now.utc

      apply_inc = apply_includes?
      apply_exc = apply_excludes?

      rc = debug_enabled? ? Hash.new(0) : nil

      debug("filter_ids_by_rules START base_count=#{base_user_ids.length} #{runtime_state_string} apply_includes=#{apply_inc} apply_excludes=#{apply_exc}")

      if apply_inc && eligible_groups.blank?
        rc_inc!(rc, :no_eligible_groups_configured)
        debug("No eligible groups configured AND apply_includes=true => filtering out all users")
        debug("reason_counters #{rc_summary_string(rc)}")
        return []
      end

      email_rows =
        UserEmail
          .where(user_id: base_user_ids, primary: true)
          .pluck(:user_id, :email)

      email_map = {}
      email_rows.each { |uid, em| email_map[uid] = em }

      rc_inc!(rc, :base_total, base_user_ids.length)
      rc_inc!(rc, :missing_primary_email, base_user_ids.length - email_map.length)

      groups_for_ref =
        []
          .tap { |arr| arr.concat(eligible_groups) if apply_inc }
          .tap { |arr| arr.concat(exclude_groups)  if apply_exc }

      emails_lists_config   = load_emails_lists_config
      sql_lists_config      = load_sql_lists_config
      referenced_list_names = collect_emails_list_names(groups_for_ref)

      # Static lists first, then merge sql lists (sql list wins on name collision)
      emails_lists_by_name  = precompute_emails_lists_by_name(referenced_list_names, emails_lists_config)
      sql_lists_by_name     = precompute_sql_lists_by_name(referenced_list_names, sql_lists_config)
      emails_lists_by_name.merge!(sql_lists_by_name)

      rc_merge_missing!(rc, find_missing_emails_list_refs_in_groups(groups_for_ref, emails_lists_by_name))

      all_cat_ids = []
      groups_for_ref.each do |g|
        next unless g.is_a?(Hash)

        if g["requires_watched_category_ids_any"].is_a?(Array)
          all_cat_ids.concat(g["requires_watched_category_ids_any"].map(&:to_i))
        end
        if g["requires_watched_category_ids_all"].is_a?(Array)
          all_cat_ids.concat(g["requires_watched_category_ids_all"].map(&:to_i))
        end
        if g["requires_watched_category_ids_min_count"].is_a?(Hash) && g["requires_watched_category_ids_min_count"]["category_ids"].is_a?(Array)
          all_cat_ids.concat(g["requires_watched_category_ids_min_count"]["category_ids"].map(&:to_i))
        end

        if g["exclude"].is_a?(Hash)
          ex = g["exclude"]
          if ex["requires_watched_category_ids_any"].is_a?(Array)
            all_cat_ids.concat(ex["requires_watched_category_ids_any"].map(&:to_i))
          end
          if ex["requires_watched_category_ids_all"].is_a?(Array)
            all_cat_ids.concat(ex["requires_watched_category_ids_all"].map(&:to_i))
          end
          if ex["requires_watched_category_ids_min_count"].is_a?(Hash) && ex["requires_watched_category_ids_min_count"]["category_ids"].is_a?(Array)
            all_cat_ids.concat(ex["requires_watched_category_ids_min_count"]["category_ids"].map(&:to_i))
          end
        end
      end
      all_cat_ids = all_cat_ids.compact.uniq

      watched_map = fetch_watched_category_map(base_user_ids, all_cat_ids)
      stats_map   = fetch_stats_map(base_user_ids)

      referenced_user_field_names = collect_user_field_names(groups_for_ref)
      field_ids_by_name = fetch_user_field_ids_by_name(referenced_user_field_names)
      user_custom_fields_map = fetch_user_custom_fields_map(base_user_ids, field_ids_by_name)

      if debug_enabled? && referenced_user_field_names.present?
        debug("user_fields referenced=#{referenced_user_field_names.join(',')} found=#{field_ids_by_name.keys.join(',')}")
      end

      kept = []
      skipped_for_attempted = []

      base_user_ids.each do |uid|
        email_raw = email_map[uid].to_s
        if email_raw.blank?
          rc_inc!(rc, :skipped_missing_email)
          skipped_for_attempted << uid
          next
        end

        email_norm = normalize_email(email_raw)
        domain     = email_domain_of(email_raw)

        watched_set = watched_map[uid] || Set.new
        stats       = stats_for_user(stats_map, uid)
        user_fields_by_name = user_custom_fields_map[uid] || {}

        args = {
          user_id: uid,
          email_domain: domain,
          watched_set: watched_set,
          stats: stats,
          now_utc: now_utc,
          email_norm: email_norm,
          emails_lists_by_name: emails_lists_by_name,
          user_fields_by_name: user_fields_by_name
        }

        excluded = false
        if apply_exc && exclude_groups.present?
          if user_matches_any_group?(exclude_groups, **args, rc: rc, context: "exclude")
            excluded = true
            rc_inc!(rc, :excluded_by_excludes)
          end
        end

        if excluded
          skipped_for_attempted << uid
          debug("user_id=#{uid} email=#{email_norm} RESULT=excluded") if debug_enabled?
          next
        end

        if apply_inc
          if user_matches_any_group?(eligible_groups, **args, rc: rc, context: "include")
            kept << uid
            rc_inc!(rc, :kept)
            debug("user_id=#{uid} email=#{email_norm} RESULT=kept") if debug_enabled?
          else
            rc_inc!(rc, :filtered_by_includes_no_match)
            skipped_for_attempted << uid
            debug("user_id=#{uid} email=#{email_norm} RESULT=filtered_no_include_match") if debug_enabled?
          end
        else
          kept << uid
          rc_inc!(rc, :kept)
          debug("user_id=#{uid} email=#{email_norm} RESULT=kept_no_include_filter") if debug_enabled?
        end
      end

      marked = mark_digest_attempted_for_users!(skipped_for_attempted, now_utc, rc: rc)
      rc_inc!(rc, :marked_digest_attempted_at_users, skipped_for_attempted.uniq.length) if rc

      debug("mark_digest_attempted_at mode=#{skipped_attempted_mode} skipped_users=#{skipped_for_attempted.uniq.length} rows=#{marked} at=#{now_utc.iso8601}")
      debug("filter_ids_by_rules END base=#{base_user_ids.length} kept=#{kept.length} skipped=#{skipped_for_attempted.uniq.length} eligible_groups=#{eligible_groups.length} exclude_groups=#{exclude_groups.length}")
      debug("reason_counters #{rc_summary_string(rc)}") if debug_enabled?

      kept
    end
  end

  if ::DigestEligibilityRules.globally_off?
    ::DigestEligibilityRules.warn("GLOBAL OFF: DIGEST_ELIGIBILITY_GLOBAL_OFF is set; plugin will not filter digests")
  end

  module ::DigestEligibilityRules
    module EnqueueDigestEmailsPatch
      def target_user_ids
        ::DigestEligibilityRules.warn("target_user_ids HIT class=#{self.class.name} #{::DigestEligibilityRules.runtime_state_string}")

        if ::DigestEligibilityRules.enabled? && ::DigestEligibilityRules.custom_query_mode?
          # ----------------------------------------------------------------
          # CUSTOM QUERY MODE: bypass Discourse's built-in SQL entirely.
          # ----------------------------------------------------------------
          ::DigestEligibilityRules.warn("target_user_ids CUSTOM_QUERY_MODE active")

          ids = ::DigestEligibilityRules.run_custom_base_query

          begin
            ::DigestEligibilityRules.warn("target_user_ids custom_query returned count=#{ids.length} sample=#{ids.first(10).inspect}")
          rescue => e
            ::DigestEligibilityRules.warn("target_user_ids custom_query log failed: #{e.class}: #{e.message}")
          end

          if ::DigestEligibilityRules.custom_query_failsafe?
            before_failsafe = ids.length
            ids = ::DigestEligibilityRules.apply_digest_failsafe_filter(ids)
            ::DigestEligibilityRules.warn("target_user_ids failsafe applied before=#{before_failsafe} after=#{ids.length} removed=#{before_failsafe - ids.length}")
          else
            ::DigestEligibilityRules.warn("target_user_ids failsafe DISABLED — using raw custom query results")
          end

          if ::DigestEligibilityRules.custom_query_recent_digest_failsafe?
            before_recent = ids.length
            ids = ::DigestEligibilityRules.apply_recent_digest_failsafe_filter(ids)
            ::DigestEligibilityRules.warn("target_user_ids recent_digest_failsafe applied hours=#{::DigestEligibilityRules.custom_query_recent_digest_hours} before=#{before_recent} after=#{ids.length} removed=#{before_recent - ids.length}")
          else
            ::DigestEligibilityRules.warn("target_user_ids recent_digest_failsafe DISABLED")
          end

          if ::DigestEligibilityRules.custom_query_recent_emailed_failsafe?
            before_emailed = ids.length
            ids = ::DigestEligibilityRules.apply_recent_emailed_failsafe_filter(ids)
            ::DigestEligibilityRules.warn("target_user_ids recent_emailed_failsafe applied hours=#{::DigestEligibilityRules.custom_query_recent_emailed_hours} before=#{before_emailed} after=#{ids.length} removed=#{before_emailed - ids.length}")
          else
            ::DigestEligibilityRules.warn("target_user_ids recent_emailed_failsafe DISABLED")
          end

          if ::DigestEligibilityRules.custom_query_apply_rules?
            out = ::DigestEligibilityRules.filter_ids_by_rules(ids)
            ::DigestEligibilityRules.warn("target_user_ids CUSTOM_QUERY_MODE rules applied count=#{out.length} sample=#{out.first(10).inspect}")
          else
            out = ids
            ::DigestEligibilityRules.warn("target_user_ids CUSTOM_QUERY_MODE rules SKIPPED count=#{out.length} sample=#{out.first(10).inspect}")
          end

          @digest_eligibility_filtered_ids = Array(out).map(&:to_i).uniq
          return out
        end

        # ----------------------------------------------------------------
        # DEFAULT MODE: call Discourse's original target_user_ids.
        # ----------------------------------------------------------------
        ids = super

        begin
          sample = ids.respond_to?(:first) ? ids.first(10) : []
          ::DigestEligibilityRules.warn("target_user_ids SUPER returned count=#{ids.length rescue 'nil'} sample=#{sample.inspect}")
        rescue => e
          ::DigestEligibilityRules.warn("target_user_ids sample/log failed: #{e.class}: #{e.message}")
        end

        unless ::DigestEligibilityRules.enabled?
          ::DigestEligibilityRules.warn("target_user_ids BYPASS because plugin disabled")
          @digest_eligibility_filtered_ids = ids
          return ids
        end

        out = ::DigestEligibilityRules.filter_ids_by_rules(ids)
        @digest_eligibility_filtered_ids = Array(out).map(&:to_i).uniq

        begin
          sample_out = out.respond_to?(:first) ? out.first(10) : []
          ::DigestEligibilityRules.warn("target_user_ids FILTERED count=#{out.length rescue 'nil'} sample=#{sample_out.inspect}")
        rescue => e
          ::DigestEligibilityRules.warn("target_user_ids filtered sample/log failed: #{e.class}: #{e.message}")
        end

        out
      rescue => e
        ::DigestEligibilityRules.warn("target_user_ids ERROR #{e.class}: #{e.message}\n#{e.backtrace&.first(15)&.join("\n")}")
        raise
      end

      def execute(args = nil)
        ::DigestEligibilityRules.warn("execute HIT class=#{self.class.name} #{::DigestEligibilityRules.runtime_state_string}")

        @digest_eligibility_filtered_ids = nil
        @digest_eligibility_stats_bumped_ids = Set.new

        result = super

        begin
          debug_ids = Array(@digest_eligibility_filtered_ids).map(&:to_i).uniq
          if debug_ids.any?
            default_delay = SiteSetting.default_email_digest_frequency.to_i

            # Mirror Jobs::UserEmail check 1:
            # return if user.user_stat.digest_attempted_at > delay.minutes.ago
            blocked_by_attempted = User
              .joins(:user_stat, :user_option)
              .where(id: debug_ids)
              .where(
                "user_stats.digest_attempted_at IS NOT NULL AND user_stats.digest_attempted_at > NOW() - (COALESCE(NULLIF(user_options.digest_after_minutes,0), ?) * INTERVAL '1 minute')",
                default_delay
              )
              .pluck(:id)
            ::DigestEligibilityRules.warn("DEBUG jobs_usemail_would_skip_digest_attempted_at count=#{blocked_by_attempted.length} sample=#{blocked_by_attempted.first(5).inspect}")

            # Mirror Jobs::UserEmail check 2:
            # return if user.last_seen_at > delay.minutes.ago
            blocked_by_seen = User
              .joins(:user_option)
              .where(id: debug_ids)
              .where(
                "users.last_seen_at IS NOT NULL AND users.last_seen_at > NOW() - (COALESCE(NULLIF(user_options.digest_after_minutes,0), ?) * INTERVAL '1 minute')",
                default_delay
              )
              .pluck(:id)
            ::DigestEligibilityRules.warn("DEBUG jobs_usemail_would_skip_last_seen_at count=#{blocked_by_seen.length} sample=#{blocked_by_seen.first(5).inspect}")

            # Mirror Jobs::UserEmail check 3:
            # return if user.user_stat.bounce_score >= bounce_score_threshold
            blocked_by_bounce = UserStat
              .where(user_id: debug_ids)
              .where("bounce_score >= ?", SiteSetting.bounce_score_threshold)
              .pluck(:user_id)
            ::DigestEligibilityRules.warn("DEBUG jobs_usemail_would_skip_bounce_score count=#{blocked_by_bounce.length} sample=#{blocked_by_bounce.first(5).inspect}")

            total_would_skip = (blocked_by_attempted | blocked_by_seen | blocked_by_bounce).length
            ::DigestEligibilityRules.warn("DEBUG jobs_usemail_total_would_skip=#{total_would_skip} out of #{debug_ids.length} enqueued")
          end
        rescue => e
          ::DigestEligibilityRules.warn("DEBUG block failed: #{e.class}: #{e.message}")
        end

        unless ::DigestEligibilityRules.enabled?
          ::DigestEligibilityRules.warn("execute SKIP stats bump because plugin disabled")
          return result
        end

        ids = Array(@digest_eligibility_filtered_ids).map(&:to_i).uniq
        if ids.empty?
          ::DigestEligibilityRules.warn("execute NO filtered ids captured; no stats bumped")
          return result
        end

        ids_to_bump = ids - @digest_eligibility_stats_bumped_ids.to_a
        now_utc = Time.now.utc
        bumped = ::DigestEligibilityRules.bump_stats_for_users!(ids_to_bump, now_utc)
        ids_to_bump.each { |id| @digest_eligibility_stats_bumped_ids << id }

        ::DigestEligibilityRules.warn("execute STATS bump complete filtered_ids=#{ids.length} bumped_now=#{bumped} sample=#{ids.first(10).inspect} at=#{now_utc.iso8601}")
        result
      rescue => e
        ::DigestEligibilityRules.warn("execute ERROR #{e.class}: #{e.message}\n#{e.backtrace&.first(15)&.join("\n")}")
        raise
      end
    end
  end

  if defined?(::Jobs::EnqueueDigestEmails)
    begin
      job_methods = ::Jobs::EnqueueDigestEmails.instance_methods(false).map(&:to_s).sort
      job_private_methods = ::Jobs::EnqueueDigestEmails.private_instance_methods(false).map(&:to_s).sort

      ::DigestEligibilityRules.warn("Jobs::EnqueueDigestEmails found. public_methods=#{job_methods.inspect}")
      ::DigestEligibilityRules.warn("Jobs::EnqueueDigestEmails found. private_methods=#{job_private_methods.inspect}")

      ::Jobs::EnqueueDigestEmails.prepend(::DigestEligibilityRules::EnqueueDigestEmailsPatch)

      ancestors_sample = ::Jobs::EnqueueDigestEmails.ancestors.take(10).map(&:to_s)
      ::DigestEligibilityRules.warn("Patched Jobs::EnqueueDigestEmails ancestors=#{ancestors_sample.inspect}")

      has_target =
        ::Jobs::EnqueueDigestEmails.instance_methods(true).map(&:to_s).include?("target_user_ids") ||
          ::Jobs::EnqueueDigestEmails.private_instance_methods(true).map(&:to_s).include?("target_user_ids")

      has_execute =
        ::Jobs::EnqueueDigestEmails.instance_methods(true).map(&:to_s).include?("execute") ||
          ::Jobs::EnqueueDigestEmails.private_instance_methods(true).map(&:to_s).include?("execute")

      ::DigestEligibilityRules.warn("Post-patch method presence target_user_ids=#{has_target} execute=#{has_execute}")
      ::DigestEligibilityRules.warn("Plugin runtime state after patch: #{::DigestEligibilityRules.runtime_state_string}")
    rescue => e
      ::DigestEligibilityRules.warn("ERROR while patching Jobs::EnqueueDigestEmails: #{e.class}: #{e.message}\n#{e.backtrace&.first(15)&.join("\n")}")
    end
  else
    ::DigestEligibilityRules.warn("ERROR: Jobs::EnqueueDigestEmails not found; plugin not applied")
  end
end
