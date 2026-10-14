#include "policy.hpp"

#include <algorithm>
#include <array>

namespace forti::engine::detail {

    namespace {

        // Management access, routing, administration, segmentation and device identity: a mistake can
        // cut off the management path or the network. Prefixes of SDK paths; "x/" covers a group.
        constexpr std::array critical_prefixes = {
                std::string_view("cmdb/router/"),            std::string_view("cmdb/router."),
                std::string_view("cmdb/system/interface"),   std::string_view("cmdb/system/admin"),
                std::string_view("cmdb/system/api-user"),    std::string_view("cmdb/system/accprofile"),
                std::string_view("cmdb/system/global"),      std::string_view("cmdb/system/settings"),
                std::string_view("cmdb/system/ha"),          std::string_view("cmdb/system/vdom"),
                std::string_view("cmdb/system/zone"),        std::string_view("cmdb/system/dns"),
                std::string_view("cmdb/system/ntp"),         std::string_view("cmdb/system/sdwan"),
                std::string_view("cmdb/system/central-management"),
                std::string_view("cmdb/system/csf"),         std::string_view("cmdb/system/password-policy"),
                std::string_view("cmdb/system/snmp"),        std::string_view("cmdb/system/switch-interface"),
                std::string_view("cmdb/system/virtual-switch"),
                std::string_view("cmdb/system/vxlan"),       std::string_view("cmdb/system/gre-tunnel"),
                std::string_view("cmdb/firewall/local-in-policy"),
                std::string_view("cmdb/certificate/"),       std::string_view("cmdb/vpn.certificate/"),
                std::string_view("cmdb/user/setting"),       std::string_view("cmdb/system/automation"),
        };

        // Changes traffic handling or authentication when they take effect.
        constexpr std::array elevated_prefixes = {
                std::string_view("cmdb/firewall/policy"),    std::string_view("cmdb/firewall/proxy-policy"),
                std::string_view("cmdb/firewall/shaping-policy"),
                std::string_view("cmdb/firewall/vip"),       std::string_view("cmdb/firewall/ippool"),
                std::string_view("cmdb/firewall/central-snat-map"),
                std::string_view("cmdb/firewall/security-policy"),
                std::string_view("cmdb/firewall/dos-policy"),
                std::string_view("cmdb/firewall/interface-policy"),
                std::string_view("cmdb/firewall/multicast-policy"),
                std::string_view("cmdb/firewall/sniffer"),   std::string_view("cmdb/firewall/ttl-policy"),
                std::string_view("cmdb/user/"),              std::string_view("cmdb/vpn/"),
                std::string_view("cmdb/vpn."),               std::string_view("cmdb/system/"),
                std::string_view("cmdb/system."),            std::string_view("cmdb/switch-controller"),
                std::string_view("cmdb/wireless-controller"),
                std::string_view("cmdb/extension-controller"),
                std::string_view("cmdb/log"),                std::string_view("cmdb/authentication/"),
        };

        // Monitor actions that can restart the device, replace its configuration or firmware, or cut a
        // management path: critical, so apply probes management connectivity after them. The rest stay
        // elevated (forti-api gap G6: monitor side effects are not catalogued). Routes from the 7.4.8
        // GUI catalog (forti-api codegen/catalog/7.4.8/gui-api.json) plus the documented firmware and HA
        // endpoints. A prefix ending in '/' or '-' covers everything below it.
        constexpr std::array critical_monitor_prefixes = {
                std::string_view("monitor/system/os/"),                 // reboot, shutdown
                std::string_view("monitor/system/config/restore"),
                std::string_view("monitor/system/config/reload"),
                std::string_view("monitor/system/config/revert"),
                std::string_view("monitor/system/config-revision/"),
                std::string_view("monitor/system/firmware/"),           // upgrade
                std::string_view("monitor/system/factory-reset"),
                std::string_view("monitor/system/change-password"),
                std::string_view("monitor/system/admin/change-vdom-mode"),
                std::string_view("monitor/system/disconnect-admins/"),
                std::string_view("monitor/system/ha-"),                 // ha-peer, ha-checksums, ...
                std::string_view("monitor/system/interface/"),
                std::string_view("monitor/system/vmlicense/"),          // a license upload reboots a VM
                std::string_view("monitor/system/certificate/"),
                std::string_view("monitor/vpn/ike/clear"),
                std::string_view("monitor/vpn/ssl/delete"),
                std::string_view("monitor/firewall/session/close-all"),
        };

        bool matches(std::string_view path, std::string_view prefix) {
            if (!path.starts_with(prefix)) return false;
            if (prefix.ends_with('/') || prefix.ends_with('.')) return true;
            // "cmdb/system/interface" must not match "cmdb/system/interface-policy" by accident,
            // but does cover "cmdb/system/interface" and dotted children ("cmdb/system.x/...").
            return path.size() == prefix.size() || path[prefix.size()] == '/' || path[prefix.size()] == '.' ||
                   path[prefix.size()] == '6';
        }

    }  // namespace

    std::string_view to_string(Risk risk) {
        switch (risk) {
            case Risk::low: return "low";
            case Risk::elevated: return "elevated";
            case Risk::critical: return "critical";
        }
        return "critical";
    }

    std::vector<std::string_view> write_operations(const Resource& resource) {
        switch (resource.kind) {
            case Kind::table: return {"create", "update", "delete"};
            case Kind::singleton: return {"update"};
            case Kind::monitor: return {"action"};
        }
        return {};
    }

    Risk risk_of(const Resource& resource) {
        if (resource.kind == Kind::monitor) {
            for (std::string_view prefix: critical_monitor_prefixes) {
                if (!resource.path.starts_with(prefix)) continue;
                if (prefix.ends_with('/') || prefix.ends_with('-') || resource.path.size() == prefix.size() ||
                    resource.path[prefix.size()] == '/')
                    return Risk::critical;
            }
            return Risk::elevated;
        }
        auto has = [&](const auto& prefixes) {
            return std::ranges::any_of(prefixes, [&](std::string_view prefix) { return matches(resource.path, prefix); });
        };
        if (has(critical_prefixes)) return Risk::critical;
        if (has(elevated_prefixes)) return Risk::elevated;
        return Risk::low;
    }

}  // namespace forti::engine::detail
