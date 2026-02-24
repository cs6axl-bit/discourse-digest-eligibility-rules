# frozen_string_literal: true
# name: discourse-digest-eligibility-rules
# about: Configurable eligibility + exclusion condition-groups (OR of AND rules) to decide who receives digest emails, incl. PG emails_list checks + optional L1/L2 caching.
# version: 2.3.0
# authors: you
# required_version: 3.0.0
# v2.3.0:
# - Adds "reason counters" summary logs (no per-user spam)
# - Counts why users were excluded / not included / missing config, etc.

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
      # never block digests
    end

    def self.warn(msg)
      Rails.logger.warn("[#{PLUGIN_NAME}] #{msg}")
    rescue
      # never block digests
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
    # Stats
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
      # ignore
    end

    def self.rc_merge_missing!(rc, miss_hash)
      return if rc.nil? || miss_hash.nil?
      miss_hash.each { |k, v| rc_inc!(rc, :"missing_emails_list:#{k}", v.to_i) }
    rescue
      # ignore
    end

    def self.rc_summary_string(rc)
      return "" if rc.nil? || rc.empty?
      # Sort by count desc then key
      pairs = rc.sort_by { |k, v| [-v.to_i, k.to_s] }
      pairs.map { |k, v| "#{k}=#{v}" }.join(" ")
    rescue
      ""
    end

    # --------------------------------
    # Watched category map (bulk)
    # user_id => Set(category_id) for watched levels
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
    # group["requires_watched_category_ids_min_count"] = {"category_ids":[...], "min_count":3}
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

    # --------------------------------
    # emails_list config (UNLIMITED)
    # SiteSetting.digest_eligibility_emails_lists_json:
    # [
    #   {"name":"A","table":"emails_list_a","column":"email"},
    #   {"name":"B","table":"emails_list_b","column":"email"}
    # ]
    # --------------------------------
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
        out[name] = { table: t, column: c } # duplicate names => last wins
      end
      out
    rescue => e
      warn("ERROR parsing digest_eligibility_emails_lists_json: #{e.class}: #{e.message}")
      {}
    end

    # --------------------------------
    # DB load: fetch ALL emails from public.<table>.<column>
    # returns Array (lowercased, uniq)
    # --------------------------------
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

    # --------------------------------
    # Fetch ALL emails with caching:
    # - L1 in-process (optional)
    # - L2 Discourse.cache (cross-process) (optional)
    # returns Set
    # --------------------------------
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

      # L1
      l1k = l1_cache_key(t, c)
      if l1_enabled? && ttl > 0
        cached = l1_cache[l1k]
        if cached && cached[:expires_at].to_i > now
          return Set.new(cached[:emails] || [])
        end
      end

      # L2
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

      # store L1
      if l1_enabled? && ttl > 0
        l1_cache[l1k] = { expires_at: now + ttl, emails: arr }
      end

      Set.new(arr)
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

    # For counters: returns { "NAME" => count_missing_refs_in_groups, ... }
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
    # Adds optional reason counters (rc)
    # --------------------------------
    def self.user_matches_group?(group, user_id:, email_domain:, watched_set:, stats:, now_utc:, email_norm:, emails_lists_by_name:, rc: nil, context: nil)
      # Nested exclude inside this group
      if group["exclude"].is_a?(Hash)
        if user_matches_group?(group["exclude"],
                               user_id: user_id,
                               email_domain: email_domain,
                               watched_set: watched_set,
                               stats: stats,
                               now_utc: now_utc,
                               email_norm: email_norm,
                               emails_lists_by_name: emails_lists_by_name,
                               rc: rc,
                               context: "nested_exclude")
          rc_inc!(rc, :"#{context || 'group'}:blocked_by_nested_exclude")
          return false
        end
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

      # Reason counters (only used when debug enabled)
      rc = debug_enabled? ? Hash.new(0) : nil

      if apply_inc && eligible_groups.blank?
        rc_inc!(rc, :no_eligible_groups_configured)
        debug("No eligible groups configured AND apply_includes=true => filtering out all users") if debug_enabled?
        # Summary line:
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

      # Missing emails_list configs referenced by any group (counts references, not users)
      rc_merge_missing!(rc, find_missing_emails_list_refs_in_groups(groups_for_ref, emails_lists_by_name))

      # Collect category IDs referenced (any/all/min_count), including nested exclude
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

      kept = []

      base_user_ids.each do |uid|
        email_raw  = email_map[uid].to_s
        if email_raw.blank?
          rc_inc!(rc, :skipped_missing_email)
          next
        end

        email_norm = normalize_email(email_raw)
        domain     = email_domain_of(email_raw)

        watched_set = watched_map[uid] || Set.new
        stats       = stats_for_user(stats_map, uid)

        args = {
          user_id: uid,
          email_domain: domain,
          watched_set: watched_set,
          stats: stats,
          now_utc: now_utc,
          email_norm: email_norm,
          emails_lists_by_name: emails_lists_by_name
        }

        excluded = false
        if apply_exc && exclude_groups.present?
          if user_matches_any_group?(exclude_groups, **args, rc: rc, context: "exclude")
            excluded = true
            rc_inc!(rc, :excluded_by_excludes)
          end
        end

        if excluded
          next
        end

        if apply_inc
          if user_matches_any_group?(eligible_groups, **args, rc: rc, context: "include")
            kept << uid
            rc_inc!(rc, :kept)
          else
            rc_inc!(rc, :filtered_by_includes_no_match)
          end
        else
          kept << uid
          rc_inc!(rc, :kept)
        end
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
