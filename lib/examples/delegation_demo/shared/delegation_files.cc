#include "examples/delegation_demo/shared/delegation_files.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <sstream>

#include "examples/delegation_demo/shared/delegation_crypto.h"
#include "examples/mdoc_anoncred/shared/files.h"

namespace proofs {
namespace {

bool EnsureDir(const std::filesystem::path& dir, std::string* err) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    if (err != nullptr) {
      *err = "failed to create directory: " + dir.string() + ": " + ec.message();
    }
    return false;
  }
  return true;
}

// ----------------------------------------------------------------
// 极简 JSON 解析工具：仅处理已知固定模式
// ----------------------------------------------------------------

// 从 JSON 字符串中提取键的字符串值
// 处理格式: "key":"value" 或 "key": "value"（允许冒号后有空格）
static std::string ExtractJsonString(const std::string& json, const std::string& key) {
  const std::string key_token = "\"" + key + "\"";
  const size_t kpos = json.find(key_token);
  if (kpos == std::string::npos) return "";
  size_t cur = kpos + key_token.size();
  // skip optional whitespace and colon
  while (cur < json.size() && (json[cur] == ' ' || json[cur] == ':' || json[cur] == '\n' || json[cur] == '\r' || json[cur] == '\t')) ++cur;
  if (cur >= json.size() || json[cur] != '"') return "";
  const size_t start = cur + 1;
  const size_t end = json.find('"', start);
  if (end == std::string::npos) return "";
  return json.substr(start, end - start);
}

// 从 JSON 字符串中提取键的字符串数组值
// 处理格式: "key":["v1","v2",...] 或 "key": ["v1", "v2"]（允许空格）
static std::vector<std::string> ExtractJsonStringArray(const std::string& json,
                                                        const std::string& key) {
  const std::string key_token = "\"" + key + "\"";
  const size_t kpos = json.find(key_token);
  if (kpos == std::string::npos) return {};
  size_t cur = kpos + key_token.size();
  // skip whitespace, colon, whitespace, open bracket
  while (cur < json.size() && json[cur] != '[') ++cur;
  if (cur >= json.size()) return {};
  ++cur;  // skip '['
  std::vector<std::string> result;
  while (cur < json.size() && json[cur] != ']') {
    if (json[cur] == '"') {
      const size_t end = json.find('"', cur + 1);
      if (end == std::string::npos) break;
      result.push_back(json.substr(cur + 1, end - cur - 1));
      cur = end + 1;
    } else {
      ++cur;
    }
  }
  return result;
}

static std::vector<PolicyPredicate> ExtractPredicates(const std::string& json) {
  std::vector<PolicyPredicate> out;
  const std::string key = "\"predicates\"";
  size_t pos = json.find(key);
  if (pos == std::string::npos) return out;
  pos = json.find('[', pos);
  if (pos == std::string::npos) return out;
  size_t end = std::string::npos;
  size_t depth = 0;
  for (size_t i = pos; i < json.size(); ++i) {
    if (json[i] == '[') {
      ++depth;
    } else if (json[i] == ']') {
      --depth;
      if (depth == 0) {
        end = i;
        break;
      }
    }
  }
  if (end == std::string::npos) return out;
  size_t cur = pos;
  while (cur < end) {
    const size_t obj = json.find('{', cur);
    if (obj == std::string::npos || obj > end) break;
    const size_t obj_end = json.find('}', obj);
    if (obj_end == std::string::npos || obj_end > end) break;
    const std::string one = json.substr(obj, obj_end - obj + 1);
    PolicyPredicate p;
    p.claim = ExtractJsonString(one, "claim");
    const std::string op = ExtractJsonString(one, "op");
    if (op == "EQ") {
      p.op = PredicateOp::EQ;
    } else if (op == "IN_SET") {
      p.op = PredicateOp::IN_SET;
    } else if (op == "GE") {
      p.op = PredicateOp::GE;
    } else if (op == "LE") {
      p.op = PredicateOp::LE;
    } else {
      p.op = PredicateOp::DISCLOSE;
    }
    p.values = ExtractJsonStringArray(one, "values");
    if (!p.claim.empty()) out.push_back(p);
    cur = obj_end + 1;
  }
  return out;
}

static void WritePredicates(std::ostringstream& oss,
                            const std::vector<PolicyPredicate>& predicates,
                            const std::string& indent) {
  oss << indent << "\"predicates\": [";
  for (size_t i = 0; i < predicates.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << "{\"claim\":\"" << predicates[i].claim << "\","
        << "\"op\":\"" << PredicateOpName(predicates[i].op)
        << "\",\"values\":[";
    for (size_t j = 0; j < predicates[i].values.size(); ++j) {
      if (j > 0) oss << ", ";
      oss << "\"" << predicates[i].values[j] << "\"";
    }
    oss << "]}";
  }
  oss << "]";
}

}  // namespace

// ----------------------------------------------------------------
// Policy JSON 读写
// ----------------------------------------------------------------

bool WritePolicyJson(const std::filesystem::path& path,
                     const Policy& policy,
                     std::string* err) {
  // 格式化输出，便于人工阅读
  std::ostringstream oss;
  oss << "{\n";
  oss << "  \"agent_id\": \"" << policy.agent_id << "\",\n";
  oss << "  \"allowed_claims\": [";
  for (size_t i = 0; i < policy.allowed_claims.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << "\"" << policy.allowed_claims[i] << "\"";
  }
  oss << "],\n";
  oss << "  \"created\": \"" << policy.created << "\",\n";
  oss << "  \"expires\": \"" << policy.expires << "\",\n";
  WritePredicates(oss, policy.predicates, "  ");
  oss << "\n";
  oss << "}\n";

  if (!EnsureDir(path.parent_path(), err)) return false;
  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    if (err != nullptr) *err = "failed to open policy file: " + path.string();
    return false;
  }
  out << oss.str();
  return out.good();
}

bool ReadPolicyJson(const std::filesystem::path& path,
                    Policy* policy,
                    std::string* err) {
  std::ifstream in(path);
  if (!in) {
    if (err != nullptr) *err = "failed to open policy file: " + path.string();
    return false;
  }
  const std::string json((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());

  policy->agent_id = ExtractJsonString(json, "agent_id");
  policy->expires  = ExtractJsonString(json, "expires");
  policy->created  = ExtractJsonString(json, "created");
  policy->allowed_claims = ExtractJsonStringArray(json, "allowed_claims");
  policy->predicates = ExtractPredicates(json);

  if (policy->expires.empty()) {
    if (err != nullptr) *err = "policy.json missing 'expires' field";
    return false;
  }
  return true;
}

// ----------------------------------------------------------------
// Delegation 目录读写
// ----------------------------------------------------------------

bool WriteDelegationDir(const std::filesystem::path& dir,
                        const HolderMdoc& holder,
                        const std::string& agent_pkx_hex,
                        const std::string& agent_pky_hex,
                        const std::string& agent_sk_hex,
                        const std::string& del_msg_hex,
                        const std::string& del_sig_hex,
                        const Policy& policy,
                        const std::vector<ReaderClaim>& allowed_claims,
                        std::string* err) {
  if (!EnsureDir(dir, err)) return false;

  // -- 复制凭证材料（与 holder/ 目录相同格式）--
  if (!WriteStringFile(dir / "device_sk.txt", holder.device_sk_hex, err) ||
      !WriteStringFile(dir / "device_pkx.txt", holder.device_pkx_hex, err) ||
      !WriteStringFile(dir / "device_pky.txt", holder.device_pky_hex, err) ||
      !WriteStringFile(dir / "doc_type.txt", holder.doc_type, err) ||
      !WriteBytesFile(dir / "device_response.cbor", holder.device_response_cbor, err)) {
    return false;
  }

  // -- Agent 临时密钥 --
  if (!WriteStringFile(dir / "agent_pkx.txt", agent_pkx_hex, err) ||
      !WriteStringFile(dir / "agent_pky.txt", agent_pky_hex, err) ||
      !WriteStringFile(dir / "agent_sk.txt", agent_sk_hex, err)) {
    return false;
  }

  // -- 委托签名材料 --
  if (!WriteStringFile(dir / "delegation_msg.txt", del_msg_hex, err) ||
      !WriteStringFile(dir / "delegation_sig.txt", del_sig_hex, err)) {
    return false;
  }

  // -- 策略 JSON --
  if (!WritePolicyJson(dir / "policy.json", policy, err)) {
    return false;
  }

  // -- 允许的 claims（平面文件格式，与 holder/claims 格式一致）--
  if (!WriteStringFile(dir / "allowed_claims_count.txt",
                       std::to_string(allowed_claims.size()), err)) {
    return false;
  }
  for (size_t i = 0; i < allowed_claims.size(); ++i) {
    const auto& c = allowed_claims[i];
    const std::string idx = std::to_string(i);
    if (!WriteStringFile(dir / ("allowed_alias_" + idx + ".txt"), c.alias, err) ||
        !WriteStringFile(dir / ("allowed_namespace_" + idx + ".txt"), c.namespace_id, err) ||
        !WriteStringFile(dir / ("allowed_id_" + idx + ".txt"), c.element_id, err) ||
        !WriteBytesFile(dir / ("allowed_cbor_value_" + idx + ".bin"), c.cbor_value, err)) {
      return false;
    }
  }
  return true;
}

bool ReadDelegationDir(const std::filesystem::path& dir,
                       HolderMdoc* holder,
                       std::string* agent_pkx_hex,
                       std::string* agent_pky_hex,
                       std::string* agent_sk_hex,
                       std::string* del_msg_hex,
                       std::string* del_sig_hex,
                       Policy* policy,
                       std::string* err) {
  // 读凭证材料
  if (!ReadStringFile(dir / "device_sk.txt", &holder->device_sk_hex, err) ||
      !ReadStringFile(dir / "device_pkx.txt", &holder->device_pkx_hex, err) ||
      !ReadStringFile(dir / "device_pky.txt", &holder->device_pky_hex, err) ||
      !ReadStringFile(dir / "doc_type.txt", &holder->doc_type, err) ||
      !ReadBytesFile(dir / "device_response.cbor", &holder->device_response_cbor, err)) {
    return false;
  }

  // 读 Agent 密钥
  if (!ReadStringFile(dir / "agent_pkx.txt", agent_pkx_hex, err) ||
      !ReadStringFile(dir / "agent_pky.txt", agent_pky_hex, err) ||
      !ReadStringFile(dir / "agent_sk.txt", agent_sk_hex, err)) {
    return false;
  }

  // 读委托签名材料
  if (!ReadStringFile(dir / "delegation_msg.txt", del_msg_hex, err) ||
      !ReadStringFile(dir / "delegation_sig.txt", del_sig_hex, err)) {
    return false;
  }

  // 读策略
  if (!ReadPolicyJson(dir / "policy.json", policy, err)) {
    return false;
  }

  // 读允许的 claims
  std::string count_str;
  if (!ReadStringFile(dir / "allowed_claims_count.txt", &count_str, err)) {
    return false;
  }
  const size_t count = static_cast<size_t>(std::stoul(count_str));
  holder->issued_claims.resize(count);
  for (size_t i = 0; i < count; ++i) {
    const std::string idx = std::to_string(i);
    auto& c = holder->issued_claims[i];
    if (!ReadStringFile(dir / ("allowed_alias_" + idx + ".txt"), &c.alias, err) ||
        !ReadStringFile(dir / ("allowed_namespace_" + idx + ".txt"), &c.namespace_id, err) ||
        !ReadStringFile(dir / ("allowed_id_" + idx + ".txt"), &c.element_id, err) ||
        !ReadBytesFile(dir / ("allowed_cbor_value_" + idx + ".bin"), &c.cbor_value, err)) {
      return false;
    }
  }
  return true;
}

// ----------------------------------------------------------------
// public_delegation.json 读写
// ----------------------------------------------------------------

bool WritePublicDelegationJson(const std::filesystem::path& path,
                              const std::string& agent_pkx_hex,
                              const std::string& agent_pky_hex,
                              const Policy& policy,
                              std::string* err) {
  if (!EnsureDir(path.parent_path(), err)) return false;

  std::ostringstream oss;
  oss << "{\n";
  oss << "  \"agent_pkx\": \"" << agent_pkx_hex << "\",\n";
  oss << "  \"agent_pky\": \"" << agent_pky_hex << "\",\n";
  oss << "  \"policy\": {\n";
  oss << "    \"agent_id\": \"" << policy.agent_id << "\",\n";
  oss << "    \"allowed_claims\": [";
  for (size_t i = 0; i < policy.allowed_claims.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << "\"" << policy.allowed_claims[i] << "\"";
  }
  oss << "],\n";
  oss << "    \"created\": \"" << policy.created << "\",\n";
  oss << "    \"expires\": \"" << policy.expires << "\",\n";
  WritePredicates(oss, policy.predicates, "    ");
  oss << "\n";
  oss << "  }\n";
  oss << "}\n";

  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    if (err != nullptr) *err = "failed to open: " + path.string();
    return false;
  }
  out << oss.str();
  return out.good();
}

bool ReadPublicDelegationJson(const std::filesystem::path& path,
                             std::string* agent_pkx_hex,
                             std::string* agent_pky_hex,
                             Policy* policy,
                             std::string* err) {
  std::ifstream in(path);
  if (!in) {
    if (err != nullptr) *err = "failed to open: " + path.string();
    return false;
  }
  const std::string json((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());

  *agent_pkx_hex  = ExtractJsonString(json, "agent_pkx");
  *agent_pky_hex  = ExtractJsonString(json, "agent_pky");

  policy->agent_id        = ExtractJsonString(json, "agent_id");
  policy->expires         = ExtractJsonString(json, "expires");
  policy->created         = ExtractJsonString(json, "created");
  policy->allowed_claims  = ExtractJsonStringArray(json, "allowed_claims");
  policy->predicates      = ExtractPredicates(json);

  if (agent_pkx_hex->empty() || agent_pky_hex->empty() ||
      policy->expires.empty()) {
    if (err != nullptr) *err = "public_delegation.json missing required fields";
    return false;
  }
  return true;
}

}  // namespace proofs
