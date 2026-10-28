#include <userver/clients/dns/component.hpp>
#include <userver/clients/http/component.hpp>
#include <userver/clients/http/component_core.hpp>
#include <userver/clients/http/component_list.hpp>
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/server/handlers/ping.hpp>
#include <userver/server/handlers/tests_control.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/testsuite/testsuite_support.hpp>
#include <userver/utils/daemon_run.hpp>

#include "hello.hpp"
#include "secret_handler.hpp"

int main(int argc, char* argv[]) {
    auto component_list = userver::components::MinimalServerComponentList()  // минимальный базовый скелет сервера
                              .Append<userver::server::handlers::Ping>()  // эндпоинт ping
                              .AppendComponentList(userver::clients::http::ComponentList())
                              .Append<userver::components::TestsuiteSupport>()  //
                              .Append<userver::clients::dns::Component>()
                              .Append<userver::server::handlers::TestsControl>()
                              .Append<userver::components::Postgres>("postgres-db-1");

    service_template::AppendHello(component_list);
    secure_pastebin::AppendCreateSecret(component_list);   
    return userver::utils::DaemonMain(argc, argv, component_list);
}