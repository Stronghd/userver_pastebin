#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <userver/components/component_list.hpp>
#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/storages/postgres/cluster.hpp>
#include <userver/yaml_config/schema.hpp>

namespace secure_pastebin {

class CreateSecretHandler final : public userver::server::handlers::HttpHandlerBase {
   public:
    static constexpr std::string_view kName = "handler-create-secret";

    CreateSecretHandler(const userver::components::ComponentConfig& config,
                        const userver::components::ComponentContext& context);

    std::string HandleRequestThrow(const userver::server::http::HttpRequest& request,
                                   userver::server::request::RequestContext& context) const override;

    static userver::yaml_config::Schema GetStaticConfigSchema();

   private:
    userver::storages::postgres::ClusterPtr pg_cluster_;
    std::string public_url_;
    std::size_t max_text_size_;
    std::size_t max_file_size_;
    std::size_t max_files_;
    std::size_t max_total_size_;
};

void AppendCreateSecret(userver::components::ComponentList& component_list);

}  // namespace secure_pastebin