// Copyright 2022 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef THIRD_PARTY_CENTIPEDE_CENTIPEDE_H_
#define THIRD_PARTY_CENTIPEDE_CENTIPEDE_H_

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "./blob_file.h"
#include "./centipede_callbacks.h"
#include "./command.h"
#include "./corpus.h"
#include "./coverage.h"
#include "./defs.h"
#include "./environment.h"
#include "./execution_result.h"
#include "./remote_file.h"
#include "./rusage_profiler.h"
#include "./stats.h"
#include "./symbol_table.h"
#include "./control_flow.h"

namespace centipede {

// The main fuzzing class.
class Centipede {
 public:
  Centipede(const Environment &env, CentipedeCallbacks &user_callbacks,
            const BinaryInfo &binary_info, CoverageLogger &coverage_logger,
            Stats &stats);
  virtual ~Centipede() {}

  // Main loop.
  void FuzzingLoop();
  // Saves the sharded corpus into `dir`, one file per input.
  // Returns 0.
  static int SaveCorpusToLocalDir(const Environment &env, std::string_view dir);
  // Exports the corpus from `dir` (one file per input) into the sharded corpus.
  // Reads `dir` recursively.
  // Ignores inputs that already exist in the shard they need to be added to.
  // Sharding is stable and depends only on env.total_shards and the file name.
  // Returns 0.
  static int ExportCorpusFromLocalDir(const Environment &env,
                                      std::string_view dir);

 private:
  // Executes inputs from `input_vec`.
  // For every input, its pruned features are written to
  // `unconditional_features_file`, (if that's non-null).
  // For every input that caused new features to be observed:
  //   * the input is added to the corpus (corpus_ and fs_ are updated).
  //   * the input is written to `corpus_file` (if that's non-null).
  //   * its features are written to `features_file` (if that's non-null).
  // Returns true if new features were observed.
  // Post-condition: `batch_result.results.size()` == `input_vec.size()`.
  bool RunBatch(const std::vector<ByteArray> &input_vec,
                BlobFileAppender *corpus_file, BlobFileAppender *features_file,
                BlobFileAppender *unconditional_features_file);
  // Loads a shard `shard_index` from `load_env.workdir`.
  // Note: `load_env_` may be different from `env_`.
  // If `rerun` is true, then also re-runs any inputs
  // for which the features are not found in `load_env.workdir`.
  void LoadShard(const Environment &load_env, size_t shard_index, bool rerun);
  // Runs all inputs from `to_rerun`, adds their features to the features file
  // of env_.my_shard_index, adds interesting inputs to the corpus.
  void Rerun(std::vector<ByteArray> &to_rerun);

  // Prints one logging line with `log_type` in it
  // if `min_log_level` is not greater than `env_.log_level`.
  void UpdateAndMaybeLogStats(std::string_view log_type, size_t min_log_level);
  // For every feature in `fv`, translates the feature into code coverage
  // (PCIndex), then prints one logging line for every
  // FUNC/EDGE observed for the first time.
  // If symbolization failed, prints a simpler logging line.
  // Uses coverage_logger_.
  void LogFeaturesAsSymbols(const FeatureVec &f);
  // Generates a coverage report file in workdir.
  void GenerateCoverageReport(std::string_view annotation, size_t batch_index);
  // Generates a corpus stats file in workdir.
  void GenerateCorpusStats(std::string_view annotation, size_t batch_index);
  // Generates the clang source-based coverage report in workdir.
  void GenerateSourceBasedCoverageReport(std::string_view annotation,
                                         size_t batch_index);
  // Generates a performance report file in workdir.
  void GenerateRUsageReport(std::string_view annotation, size_t batch_index);
  // Generates all the report and stats files in workdir if this shard is
  // assigned to do that and if `batch_index` == 0 or satisfies the criteria set
  // via the flags.
  void MaybeGenerateTelemetry(std::string_view annotation, size_t batch_index);

  // Returns true if `input` passes env_.input_filter.
  bool InputPassesFilter(const ByteArray &input);
  // Executes `binary` with `input_vec` and `batch_result` as input/output.
  // If the binary crashes, calls ReportCrash().
  // Returns true iff there were no crashes.
  bool ExecuteAndReportCrash(std::string_view binary,
                             const std::vector<ByteArray> &input_vec,
                             BatchResult &batch_result);
  // Reports a crash and saves the reproducer to workdir/crashes, if possible.
  // `binary` is the binary causing the crash.
  // Prints the first `env_.max_num_crash_reports` logs.
  // `input_vec` is the batch of inputs that caused a crash.
  // `batch_result` contains the features computed for `input_vec`
  // (batch_result.results().size() == input_vec.size()). `batch_result` is used
  // as a hint when choosing which input to try first.
  void ReportCrash(std::string_view binary,
                   const std::vector<ByteArray> &input_vec,
                   const BatchResult &batch_result);
  // Merges shard `shard_index_to_merge` of the corpus in `merge_from_dir`
  // into the current corpus.
  // Writes added inputs to the current shard.
  void MergeFromOtherCorpus(std::string_view merge_from_dir,
                            size_t shard_index_to_merge);

  // Collects all PCs from `fv`, then adds PC-pair features to `fv`.
  // Returns the number of added features.
  // See more comments in centipede.cc.
  size_t AddPcPairFeatures(FeatureVec &fv);

  const Environment &env_;
  CentipedeCallbacks &user_callbacks_;
  Rng rng_;

  // A timestamp set just before the actual fuzzing begins. Used to measure
  // the fuzzing performance.
  absl::Time fuzz_start_time_ = absl::InfiniteFuture();

  FeatureSet fs_;
  Corpus corpus_;
  CoverageFrontier coverage_frontier_;
  size_t num_runs_ = 0;  // counts executed inputs

  // Binary-related data, initialized at startup, once per process,
  // by calling the PopulateBinaryInfo callback.
  const PCTable &pc_table_;
  const SymbolTable &symbols_;
  // TODO(ussuri): Replace usages of the above two with matching binary_info_
  //  members.
  const BinaryInfo &binary_info_;

  // Derived from env_.function_filter. Currently, duplicated by every thread.
  // In future, threads may have different filters.
  const FunctionFilter function_filter_;

  // Ensures every coverage location is reported at most once.
  // This object is shared with other threads, it is thread-safe.
  CoverageLogger &coverage_logger_;

  // Statistics of the current run.
  Stats &stats_;

  // Counts the number of crashes reported so far.
  int num_crash_reports_ = 0;

  // Scratch object for AddPcPairFeatures.
  std::vector<size_t> add_pc_pair_scratch_;

  // Path and command for the input_filter.
  std::string input_filter_path_;
  Command input_filter_cmd_;

  // Resource usage stats collection & reporting.
  perf::RUsageProfiler rusage_profiler_;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_CENTIPEDE_H_
