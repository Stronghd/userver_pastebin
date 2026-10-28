#include "secret_handler.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <string>
#include <system_error>
#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/formats/json/serialize.hpp>
#include <userver/formats/json/value_builder.hpp>
#include <userver/http/content_type.hpp>
#include <userver/server/handlers/exceptions.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/server/http/http_status.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/storages/postgres/io/bytea.hpp>
#include <userver/storages/postgres/io/chrono.hpp>
#include <userver/storages/postgres/query.hpp>
#include <userver/storages/postgres/transaction.hpp>
#include <userver/utils/datetime.hpp>
#include <userver/utils/uuid4.hpp>
#include <userver/yaml_config/merge_schemas.hpp>
#include <vector>

namespace secure_pastebin {

namespace {

constexpr std::int64_t kDefaultTtlSeconds = 3600;
constexpr std::int64_t kMinTtlSeconds = 60;
constexpr std::int64_t kMaxTtlSeconds = 604800;
constexpr const char* kDefaultFilename = "file";
constexpr const char* kDefaultContentType = "application/octet-stream";
const userver::storages::postgres::Query kInsertSecret{
    "INSERT INTO secrets (id, encrypted_payload, text_size_bytes, expires_at) "
    "VALUES ($1::uuid, NULLIF($2, ''::bytea), $3, $4)",
    userver::storages::postgres::Query::Name{"insert_secret"},
};
const userver::storages::postgres::Query kInsertAttachment{
    "INSERT INTO attachments (id, secret_id, position, filename, content_type, size_bytes, encrypted_payload) VALUES "
    "($1::uuid, $2::uuid, $3, $4, $5, $6, $7)",
    userver::storages::postgres::Query::Name{"insert_attachment"},
};

struct ParsedFile {
    std::string id;
    std::string filename;
    std::string content_type;
    std::string_view data;
};

[[noreturn]] void ThrowBadRequest(std::string_view message) {
    throw userver::server::handlers::ClientError(userver::server::handlers::ExternalBody{std::string{message}});
}

std::int64_t ParseTtl(std::string_view text) {
    std::int64_t val = 0;

    const auto result = std::from_chars(text.data(), text.data() + text.size(), val);

    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        ThrowBadRequest("ttl_seconds must be an integer( ");
    }
    if (val < kMinTtlSeconds || val > kMaxTtlSeconds) {
        ThrowBadRequest("ttl_seconds must be in range 60..604800");
    }
    return val;
}

}  // namespace

CreateSecretHandler::CreateSecretHandler(const userver::components::ComponentConfig& config,
                                         const userver::components::ComponentContext& context)
    : HttpHandlerBase(config, context),
      pg_cluster_(context.FindComponent<userver::components::Postgres>("postgres-db-1").GetCluster()),
      public_url_(config["public-url"].As<std::string>()),
      max_text_size_(config["max-text-size"].As<std::size_t>()),
      max_file_size_(config["max-file-size"].As<std::size_t>()),
      max_files_(config["max-files"].As<std::size_t>()),
      max_total_size_(config["max-total-size"].As<std::size_t>()) {}

userver::yaml_config::Schema CreateSecretHandler::GetStaticConfigSchema() {
    return userver::yaml_config::MergeSchemas<userver::server::handlers::HttpHandlerBase>(R"(
type: object
description: handler for creating secrets
additionalProperties: false
properties:
      public-url:
          type: string
          description: public base url of the server
      max-text-size:
          type: integer
          description: max text size in bytes
      max-file-size:
          type: integer
          description: max file size in bytes
      max-files:
          type: integer
          description: max files count
      max-total-size:
          type: integer
          description: max total size
)");
}

std::string CreateSecretHandler::HandleRequestThrow(const userver::server::http::HttpRequest& request,
                                                    userver::server::request::RequestContext&) const {
    namespace pg = userver::storages::postgres;

    const std::string_view content = request.GetFormDataArg("content").value;
    const bool has_text = !content.empty();

    std::int64_t ttl_seconds = kDefaultTtlSeconds;
    if (request.HasFormDataArg("ttl_seconds")) {
        ttl_seconds = ParseTtl(request.GetFormDataArg("ttl_seconds").value);
    }

    const auto& files = request.GetFormDataArgVector("files");
    if (!has_text && files.empty()) {
        ThrowBadRequest("content or at least one file is required");
    }
    if (files.size() > max_files_) {
        ThrowBadRequest("too many files");
    }
    if (content.size() > max_text_size_) {
        ThrowBadRequest("content is too large");
    }

    std::size_t total_size = content.size();
    std::vector<ParsedFile> parsed_files;
    parsed_files.reserve(files.size());

    for (const auto& file : files) {
        const std::size_t size = file.value.size();
        if (size == 0) {
            ThrowBadRequest("empty file");
        }
        if (size > max_file_size_) {
            ThrowBadRequest("too large file");
        }
        total_size += size;

        parsed_files.push_back(ParsedFile{
            userver::utils::generators::GenerateUuid(),
            file.filename.value_or(kDefaultFilename),
            std::string{file.content_type.value_or(kDefaultContentType)},
            file.value,
        });
    }

    if (total_size > max_total_size_) {
        ThrowBadRequest("too large total content size");
    }

    // --- запись в базу: все проверки выше, транзакция ниже ---
    const std::string secret_id = userver::utils::generators::GenerateUuid();
    const auto expires_at = userver::utils::datetime::Now() + std::chrono::seconds{ttl_seconds};

    auto trx = pg_cluster_->Begin("create_secret", pg::ClusterHostType::kMaster, {});

    trx.Execute(kInsertSecret,
                secret_id,
                pg::Bytea(content),
                static_cast<std::int64_t>(content.size()),
                pg::TimePointTz{expires_at});

    for (std::size_t i = 0; i < parsed_files.size(); ++i) {
        const auto& file = parsed_files[i];
        trx.Execute(kInsertAttachment,
                    file.id,
                    secret_id,
                    static_cast<std::int32_t>(i),
                    file.filename,
                    file.content_type,
                    static_cast<std::int64_t>(file.data.size()),
                    pg::Bytea(file.data));
    }

    trx.Commit();

    // --- ответ ---
    userver::formats::json::ValueBuilder response;
    response["id"] = secret_id;
    response["url"] = public_url_ + "/api/v1/secrets/" + secret_id;
    response["expires_at"] = userver::utils::datetime::Timestring(expires_at);
    response["has_text"] = has_text;

    userver::formats::json::ValueBuilder attachments(userver::formats::common::Type::kArray);
    for (const auto& file : parsed_files) {
        userver::formats::json::ValueBuilder item;
        item["id"] = file.id;
        item["filename"] = file.filename;
        item["content_type"] = file.content_type;
        item["size_bytes"] = static_cast<std::int64_t>(file.data.size());
        attachments.PushBack(std::move(item));
    }
    response["attachments"] = std::move(attachments);

    auto& http_response = request.GetHttpResponse();
    http_response.SetStatus(userver::server::http::HttpStatus::kCreated);
    http_response.SetContentType(userver::http::content_type::kApplicationJson);
    return userver::formats::json::ToString(response.ExtractValue());
}

void AppendCreateSecret(userver::components::ComponentList& component_list) {
    component_list.Append<CreateSecretHandler>();
}

}  // namespace secure_pastebin