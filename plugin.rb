# frozen_string_literal: true
# name: discourse-digest-eligibility-rules
# about: Configurable eligibility + exclusion condition-groups (OR of AND rules) to decide who receives digest emails, incl. PG emails_list checks + optional L1/L2 caching.
# version: 2.6.0
# authors: you
# required_version: 3.0.0
# v2.6.0:
# - Adds eligibility checks based on Discourse custom user fields by *field name*:
#     requires_user_field_equals_any: [{field:"file", values:["a.csv","b.csv"]}, ...]
#     requires_user_field_equals_all: [{field:"gender", values:["female"]}, ...]
#   Works in include groups, exclude groups, and nested exclude.
# - Bulk loads user_fields + user_custom_fields for base_user_ids for referenced fields (fast).

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
      data
    rescue => e
      warn("bump_stats failed user_id=#{user_id}: #{e.class}: #{e.message}")
      nil
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
          debug("emails_list L2 HIT key=#{l2k} rows=#{arr.length}") if debug_enabled?
        rescue => e
          debug("emails_list L2 fetch failed key=#{l2k}: #{e.class}: #{e.message}")
          arr = nil
        end
      end

      arr ||= load_all_emails_array_from_pg(t, c)

      if l1_enabled? && ttl > 0
        l1_cache[l1k] = { expires_at: now + ttl, emails: arr }
      end

      Set.new(arr)
    end

    # --------------------------------
    # NEW: User field requirements (by field *name*)
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

    # Returns map: field_name => field_id
    def self.fetch_user_field_ids_by_name(field_names)
      names = Array(field_names).map { |x| x.to_s.strip }.reject(&:blank?).uniq
      return {} if names.empty?
      UserField.where(name: names).pluck(:name, :id).to_h
    rescue => e
      warn("fetch_user_field_ids_by_name failed: #{e.class}: #{e.message}")
      {}
    end

    # Returns map: user_id => { "file"=>"abc", "gender"=>"female", ... } for referenced fields only
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

      # OR across clauses: any clause satisfied => pass
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

      # AND across clauses: every clause must be satisfied
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

      # NEW: user field checks
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

      if apply_inc && eligible_groups.blank?
        rc_inc!(rc, :no_eligible_groups_configured)
        debug("No eligible groups configured AND apply_includes=true => filtering out all users") if debug_enabled?
        debug("reason_counters #{rc_summary_string(rc)}") if debug_enabled?
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
      referenced_list_names = collect_emails_list_names(groups_for_ref)
      emails_lists_by_name  = precompute_emails_lists_by_name(referenced_list_names, emails_lists_config)

      rc_merge_missing!(rc, find_missing_emails_list_refs_in_groups(groups_for_ref, emails_lists_by_name))

      # categories referenced
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

      # NEW: user field references + bulk load
      referenced_user_field_names = collect_user_field_names(groups_for_ref)
      field_ids_by_name = fetch_user_field_ids_by_name(referenced_user_field_names)
      user_custom_fields_map = fetch_user_custom_fields_map(base_user_ids, field_ids_by_name)

      if debug_enabled? && referenced_user_field_names.present?
        debug("user_fields referenced=#{referenced_user_field_names.join(',')} found=#{field_ids_by_name.keys.join(',')}")
      end

      kept = []
      skipped_for_attempted = []

      base_user_ids.each do |uid|
        email_raw  = email_map[uid].to_s
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
          next
        end

        if apply_inc
          if user_matches_any_group?(eligible_groups, **args, rc: rc, context: "include")
            kept << uid
            rc_inc!(rc, :kept)
          else
            rc_inc!(rc, :filtered_by_includes_no_match)
            skipped_for_attempted << uid
          end
        else
          kept << uid
          rc_inc!(rc, :kept)
        end
      end

      marked = mark_digest_attempted_for_users!(skipped_for_attempted, now_utc, rc: rc)
      rc_inc!(rc, :marked_digest_attempted_at_users, skipped_for_attempted.uniq.length) if rc

      if debug_enabled?
        debug("mark_digest_attempted_at mode=#{skipped_attempted_mode} skipped_users=#{skipped_for_attempted.uniq.length} rows=#{marked} at=#{now_utc.iso8601}")
      end

      debug("filter_ids_by_rules base=#{base_user_ids.length} kept=#{kept.length} apply_includes=#{apply_inc} apply_excludes=#{apply_exc} eligible_groups=#{eligible_groups.length} exclude_groups=#{exclude_groups.length}")
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
        ids = super
        return ids unless ::DigestEligibilityRules.enabled?
        ::DigestEligibilityRules.filter_ids_by_rules(ids)
      end

      def enqueue_for_user(user_id)
        super
        return unless ::DigestEligibilityRules.enabled?
        ::DigestEligibilityRules.bump_stats!(user_id, Time.now.utc)
      end
    end
  end

  if defined?(::Jobs::EnqueueDigestEmails)
    ::Jobs::EnqueueDigestEmails.prepend(::DigestEligibilityRules::EnqueueDigestEmailsPatch)
    ::DigestEligibilityRules.debug("Patched Jobs::EnqueueDigestEmails")
  else
    ::DigestEligibilityRules.warn("ERROR: Jobs::EnqueueDigestEmails not found; plugin not applied")
  end
end
