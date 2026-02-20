# frozen_string_literal: true

# name: discourse-digest-eligibility-rules
# about: Configurable eligibility + exclusion condition-groups (OR of AND rules) to decide who receives digest emails, incl. PG allowlist checks + caching.
# version: 1.3.0
# authors: you
# required_version: 3.0.0

enabled_site_setting :digest_eligibility_rules_enabled

after_initialize do
  require "json"
  require "time"
  require "set"
  require "digest"

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
    # - UI: digest_eligibility_rules_enabled
    # - ENV: DIGEST_ELIGIBILITY_GLOBAL_OFF=1 (hard off)
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
    # Plugin-tracked digest stats
    # (enqueue-time tracking: count + last_digest_at_utc)
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

      cnt = (data["digest_count"].to_i rescue 0)
      cnt += 1

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
    # PG allowlist cache (in-process, TTL)
    # same style as your @domain_metrics_cache
    # --------------------------------
    def self.pg_allowlist_cache
      @pg_allowlist_cache ||= {}
    end

    def self.pg_allowlist_cache_enabled?
      SiteSetting.digest_eligibility_pg_allowlist_cache_enabled
    rescue
      false
    end

    def self.pg_allowlist_cache_ttl
      v = (SiteSetting.digest_eligibility_pg_allowlist_cache_ttl_seconds || 900).to_i
      v = 0 if v < 0
      v
    rescue
      900
    end

    def self.default_pg_table
      SiteSetting.digest_eligibility_pg_allowlist_table.to_s.strip
    rescue
      ""
    end

    def self.default_pg_column
      c = SiteSetting.digest_eligibility_pg_allowlist_column.to_s.strip
      c = "email" if c.blank?
      c
    rescue
      "email"
    end

    # Collect all (table,column) pairs referenced by groups that use requires_email_in_pg_table
    def self.collect_pg_allowlist_pairs(groups)
      pairs = []
      groups.each do |g|
        next unless g.is_a?(Hash)
        next unless g["requires_email_in_pg_table"] == true

        t = g["pg_table"].to_s.strip
        c = g["pg_column"].to_s.strip
        t = default_pg_table if t.blank?
        c = default_pg_column if c.blank?

        pairs << [t, c] if t.present? && c.present?
      end
      pairs.uniq
    end

    # Fetch which of the provided emails exist in public.<table>.<column>.
    # Uses ::DB.query with IN (?, ?, ...) style binds (same pattern as your router),
    # chunked to avoid huge placeholder lists.
    def self.fetch_allowlisted_emails_from_pg(emails, table_name, column_name)
      emails_norm = Array(emails).map { |e| normalize_email(e) }.reject(&:blank?).uniq
      return Set.new if emails_norm.empty?

      t = table_name.to_s.strip
      c = column_name.to_s.strip
      c = "email" if c.blank?

      unless valid_ident?(t) && valid_ident?(c)
        warn("allowlist invalid identifiers table=#{t.inspect} col=#{c.inspect} (must match #{IDENT_RE})")
        return Set.new
      end

      ttl = pg_allowlist_cache_ttl
      now = Time.now.to_i
      cache_key = nil

      if pg_allowlist_cache_enabled? && ttl > 0
        hash = Digest::SHA256.hexdigest(emails_norm.sort.join("\n"))
        cache_key = "public.#{t}.#{c}:#{hash}"

        cached = pg_allowlist_cache[cache_key]
        if cached && cached[:expires_at].to_i > now
          arr = cached[:emails] || []
          return Set.new(arr.map { |x| x.to_s.strip.downcase }.reject(&:blank?))
        end
      end

      table_ref = %Q{"public"."#{t}"}
      col_ref   = %Q{"#{c}"}

      out = []

      begin
        chunk_size = 500
        emails_norm.each_slice(chunk_size) do |chunk|
          placeholders = (["?"] * chunk.length).join(",")
          sql = <<~SQL
            SELECT lower(#{col_ref}) AS email
            FROM #{table_ref}
            WHERE lower(#{col_ref}) IN (#{placeholders})
          SQL

          res = ::DB.query(sql, *chunk)

          ary =
            if res.is_a?(Array)
              res
            elsif res.respond_to?(:to_a)
              tmp = res.to_a
              tmp.is_a?(Array) ? tmp : []
            else
              []
            end

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
        end
      rescue => e
        warn("allowlist query failed table=public.#{t} col=#{c}: #{e.class}: #{e.message}")
        out = []
      end

      out.uniq!
      set = Set.new(out)

      if cache_key && pg_allowlist_cache_enabled? && ttl > 0
        pg_allowlist_cache[cache_key] = { expires_at: now + ttl, emails: out }
        debug("allowlist cache store key=#{cache_key} hits=#{out.length} ttl=#{ttl}s")
      end

      set
    end

    # Precompute allowlist sets for each referenced (table,col) pair
    # returns { "table|col" => Set(allowed_emails) }
    def self.precompute_pg_allowlists_for_emails(groups, all_emails)
      out = {}
      pairs = collect_pg_allowlist_pairs(groups)
      return out if pairs.blank?

      pairs.each do |t, c|
        key = "#{t}|#{c}"
        out[key] = fetch_allowlisted_emails_from_pg(all_emails, t, c)
        debug("pg_allowlist precomputed key=#{key} hits=#{out[key].length}")
      end

      out
    end

    # --------------------------------
    # Group evaluation
    # --------------------------------
    def self.user_matches_group?(group, user_id:, email_domain:, watched_set:, stats:, now_utc:, email_norm:, pg_allowlists:)
      # Optional per-group exclude (AND block)
      if group["exclude"].is_a?(Hash)
        if user_matches_group?(group["exclude"],
                               user_id: user_id,
                               email_domain: email_domain,
                               watched_set: watched_set,
                               stats: stats,
                               now_utc: now_utc,
                               email_norm: email_norm,
                               pg_allowlists: pg_allowlists)
          return false
        end
      end

      # Email domain allow/deny
      if group["email_domain_in"].is_a?(Array)
        allowed = group["email_domain_in"].map { |x| x.to_s.downcase.strip }.reject(&:blank?).uniq
        return false if allowed.present? && !allowed.include?(email_domain)
      end

      if group["email_domain_not_in"].is_a?(Array)
        blocked = group["email_domain_not_in"].map { |x| x.to_s.downcase.strip }.reject(&:blank?).uniq
        return false if blocked.present? && blocked.include?(email_domain)
      end

      # Watched categories (any/all)
      if group["requires_watched_category_ids_any"].is_a?(Array)
        req = group["requires_watched_category_ids_any"].map(&:to_i).uniq
        return false if req.present? && (watched_set.nil? || (watched_set & req).empty?)
      end

      if group["requires_watched_category_ids_all"].is_a?(Array)
        req = group["requires_watched_category_ids_all"].map(&:to_i).uniq
        if req.present?
          return false if watched_set.nil?
          req.each { |cid| return false unless watched_set.include?(cid) }
        end
      end

      # Plugin-tracked digest constraints
      digest_count = stats["digest_count"].to_i rescue 0
      last_at = parse_time_utc(stats["last_digest_at_utc"])

      if group.key?("max_digest_count")
        maxc = group["max_digest_count"].to_i
        return false if maxc >= 0 && digest_count > maxc
      end

      if group.key?("min_days_since_last_digest")
        mind = group["min_days_since_last_digest"].to_i
        if last_at
          days = (now_utc - last_at) / 86400.0
          return false if days < mind
        end
      end

      if group.key?("max_days_since_last_digest")
        maxd = group["max_days_since_last_digest"].to_i
        return false unless last_at
        days = (now_utc - last_at) / 86400.0
        return false if days > maxd
      end

      # NEW: requires email in PG allowlist table
      if group["requires_email_in_pg_table"] == true
        t = group["pg_table"].to_s.strip
        c = group["pg_column"].to_s.strip
        t = default_pg_table if t.blank?
        c = default_pg_column if c.blank?

        # Misconfigured => fail closed
        return false if t.blank? || c.blank?

        key = "#{t}|#{c}"
        set = pg_allowlists[key]
        return false unless set.is_a?(Set)
        return false unless set.include?(email_norm)
      end

      true
    end

    def self.user_matches_any_group?(groups, **kwargs)
      groups.each do |g|
        next unless g.is_a?(Hash)
        return true if user_matches_group?(g, **kwargs)
      end
      false
    end

    # --------------------------------
    # Main filter
    # 1) hard excludes
    # 2) must match at least one eligible group
    # --------------------------------
    def self.filter_ids_by_rules(base_user_ids)
      return base_user_ids if base_user_ids.blank?

      eligible_groups = load_eligible_groups
      exclude_groups  = load_exclude_groups

      if eligible_groups.blank?
        debug("No eligible groups configured => filtering out all users")
        return []
      end

      now_utc = Time.now.utc

      # Bulk primary emails
      email_rows =
        UserEmail
          .where(user_id: base_user_ids, primary: true)
          .pluck(:user_id, :email)

      email_map = {}
      email_rows.each { |uid, em| email_map[uid] = em }

      all_emails = email_map.values.compact

      # Precompute PG allowlists for all referenced pairs (eligible + excludes + nested excludes not supported for allowlist in this minimal version)
      pg_allowlists = precompute_pg_allowlists_for_emails(eligible_groups + exclude_groups, all_emails)

      # Collect all category IDs referenced
      all_cat_ids = []
      [eligible_groups, exclude_groups].each do |groups|
        groups.each do |g|
          next unless g.is_a?(Hash)
          if g["requires_watched_category_ids_any"].is_a?(Array)
            all_cat_ids.concat(g["requires_watched_category_ids_any"].map(&:to_i))
          end
          if g["requires_watched_category_ids_all"].is_a?(Array)
            all_cat_ids.concat(g["requires_watched_category_ids_all"].map(&:to_i))
          end
          if g["exclude"].is_a?(Hash)
            ex = g["exclude"]
            if ex["requires_watched_category_ids_any"].is_a?(Array)
              all_cat_ids.concat(ex["requires_watched_category_ids_any"].map(&:to_i))
            end
            if ex["requires_watched_category_ids_all"].is_a?(Array)
              all_cat_ids.concat(ex["requires_watched_category_ids_all"].map(&:to_i))
            end
          end
        end
      end
      all_cat_ids = all_cat_ids.compact.uniq

      watched_map = fetch_watched_category_map(base_user_ids, all_cat_ids)
      stats_map   = fetch_stats_map(base_user_ids)

      kept = []

      base_user_ids.each do |uid|
        email_raw  = email_map[uid].to_s
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
          pg_allowlists: pg_allowlists
        }

        # 1) excludes (hard block)
        if exclude_groups.present? && user_matches_any_group?(exclude_groups, **args)
          next
        end

        # 2) eligible groups (must match at least one)
        if user_matches_any_group?(eligible_groups, **args)
          kept << uid
        end
      end

      debug("filter_ids_by_rules base=#{base_user_ids.length} kept=#{kept.length} eligible_groups=#{eligible_groups.length} exclude_groups=#{exclude_groups.length}")
      kept
    end
  end

  # Announce hard-off at boot
  if ::DigestEligibilityRules.globally_off?
    ::DigestEligibilityRules.warn("GLOBAL OFF: DIGEST_ELIGIBILITY_GLOBAL_OFF is set; plugin will not filter digests")
  end

  # --------------------------------
  # Patch the digest enqueue job
  # --------------------------------
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
