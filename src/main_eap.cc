#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <vector>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "cmake_vars_eap.h"
#include "common.h"
#include "eap.h"
#include "key_store.h"
#include "patch.h"

#include "banned.h"

DEFINE_bool(decrypt, false, "Run in decryption mode");
DEFINE_bool(encrypt, false, "Run in encryption mode");
DEFINE_string(input, "C0010001", "Path of the EAP KBL file to load");
DEFINE_string(keys, "keys.json", "Path of the key file to load");
DEFINE_string(output, "C0010001.modified", "Path to save the output EAP KBL file");
DEFINE_string(revision, "", "Which southbridge revision keyset to use. Only used for encryption (\"AEOLIA\", \"BELIZE\", \"BELIZE 2\", or \"BAIKAL\")");

int main(int argc, char *argv[]) {
  gflags::SetUsageMessage(g_AppDescription);
  gflags::SetVersionString(g_AppVersion);

  gflags::ParseCommandLineFlags(&argc, &argv, true);

  google::InitGoogleLogging(argv[0]);
  google::InstallFailureSignalHandler();

  if (!InitializeKeyStore(FLAGS_keys)) {
    LOG(FATAL) << "Could not read key file: " << FLAGS_keys;
    return 1;
  }

  if (FLAGS_decrypt && FLAGS_encrypt) {
    LOG(FATAL) << "Cannot use both \"encrypt\" or \"decrypt\" flag at the same time";
    return 1;
  }
  if (!FLAGS_decrypt && !FLAGS_encrypt) {
    LOG(FATAL) << "Must use \"encrypt\" or \"decrypt\" flag";
    return 1;
  }
  bool s_Encrypt{false};
  std::string s_SouthbridgeRevision;
  if (FLAGS_encrypt) {
    s_Encrypt = true;
    if (FLAGS_revision != "AEOLIA" && FLAGS_revision != "BELIZE" && FLAGS_revision != "BELIZE 2" && FLAGS_revision != "BAIKAL") {
      LOG(FATAL) << "Invalid southbridge revision: " << FLAGS_revision << "\nMust be \"AEOLIA\", \"BELIZE\", \"BELIZE 2\", or \"BAIKAL\"";
      return 1;
    }
    s_SouthbridgeRevision = FLAGS_revision;
  }

  if (FLAGS_input == FLAGS_output) {
    LOG(FATAL) << "Input and output path cannot be the same";
    return 1;
  }

  std::filesystem::path s_InputPath(FLAGS_input);
  std::filesystem::path s_OutputPath(FLAGS_output);
  if (FLAGS_input != "C0010001" && FLAGS_output == "C0010001.modified") {
    s_OutputPath = s_InputPath;
    s_OutputPath += ".modified";
  }

  gflags::ShutDownCommandLineFlags();

  LOG(INFO) << "Initalizing...";

  std::ifstream s_InputFile(s_InputPath, std::ios::in | std::ios::binary);
  if (!s_InputFile || !s_InputFile.good()) {
    s_InputFile.close();
    LOG(FATAL) << "Unable to open input file " << s_InputPath;
    return 1;
  }
  uint64_t s_InputLen{std::filesystem::file_size(s_InputPath)};

  std::vector<unsigned char> s_InputData(s_InputLen);
  if (!s_InputFile.read(reinterpret_cast<char *>(&s_InputData[0]), s_InputData.size()).good()) { // Flawfinder: ignore
    s_InputFile.close();
    LOG(FATAL) << "Unable to read input file " << s_InputPath;
    return 1;
  }
  s_InputFile.close();

  std::vector<unsigned char> s_OutputData;
  if (s_Encrypt) {
    if (!eap::EncryptKbl(&s_InputData[0], s_InputLen, s_SouthbridgeRevision, s_OutputData)) {
      LOG(FATAL) << "Failed to encrypt EAP KBL";
      return 1;
    }
  } else {
    if (!eap::DecryptKbl(&s_InputData[0], s_InputLen, s_OutputData)) {
      LOG(FATAL) << "Failed to decrypt EAP KBL";
      return 1;
    }
  }

  if (s_OutputData.size() == 0) {
    LOG(FATAL) << "Failed to modify EAP KBL";
    return 1;
  }

  if (!WriteFile(&s_OutputData[0], s_OutputData.size(), s_OutputPath)) {
    LOG(FATAL) << "Failed to write output to file to " << s_OutputPath;
    return 1;
  }

  LOG(INFO) << "Done, file saved to " << s_OutputPath;

  return 0;
}
