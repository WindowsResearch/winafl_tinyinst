/*
Copyright 2023 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "tinyinst_covmap.h"
#include "tinyinst_afl.h"
#include "common.h"

static TinyInstCovMap* instrumentation;
static bool persist;
static int num_iterations;
static int cur_iteration;

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};
extern "C" int sig = 1;
extern "C" int tinyinst_init(int argc, char** argv) {
  int lastoption = -1;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      lastoption = i;
      break;
    }
  }

  if (lastoption <= 0) return 0;

  instrumentation = new TinyInstCovMap();
  instrumentation->Init(lastoption - 1, argv + 1);

  persist = GetBinaryOption("-persist", lastoption - 1, argv + 1, false);
  num_iterations = GetIntOption("-iterations", lastoption - 1, argv + 1, 1);
  cur_iteration = 0;

  return lastoption;
}

extern "C" void tinyinst_set_fuzzer_id(char *fuzzer_id) {
  std::string shm_name = "afl_shm_default";
  if (fuzzer_id) {
    shm_name = std::string("afl_shm_") + std::string(fuzzer_id);
  }
  instrumentation->SetSHMName(shm_name);
}

int get_argc(char** argv) {
  int argc = 0;
  while (1) {
    if (!(*argv)) break;
    argv++;
    argc++;
  }
  return argc;
}

extern "C" int tinyinst_run(char** argv, uint32_t timeout, uint64_t pid) {
   uint32_t init_timeout = timeout;
  DebuggerStatus status;
  int ret = FAULT_NONE;
  
  if (instrumentation->IsTargetFunctionDefined()) {
    if (cur_iteration == num_iterations) {
      instrumentation->Kill();
      cur_iteration = 0;
    }
  }

  uint32_t timeout1 = timeout;
  if (instrumentation->IsTargetFunctionDefined()) {
    timeout1 = init_timeout;
  }

  if (instrumentation->IsTargetAlive() && persist) {
    status = instrumentation->Continue(timeout1);
  } else {
    instrumentation->Kill();
    cur_iteration = 0;
    status = instrumentation->Attach(pid, timeout1);
  }
  printf("sig is :%d\n", sig);
  if (instrumentation->IsTargetFunctionDefined()) {
    while (sig) {
      status = instrumentation->Continue(timeout1);
      switch (status) {
      case DEBUGGER_CRASHED:
        ret = FAULT_CRASH;
        instrumentation->Kill();
        return ret;
        break;
      case DEBUGGER_HANGED:
      case DEBUGGER_TARGET_END:
      case DEBUGGER_TARGET_START:
        ret = FAULT_NONE;
        break;
      case DEBUGGER_PROCESS_EXIT:
        ret = FAULT_NONE;
        FATAL("Process Exit!!!\n");
        break;
      default:
        FATAL("Unexpected status received from the debugger\n");
        break;
      }
    }
    cur_iteration++;
    return ret;
  }
  return ret;  
}

extern "C" void tinyinst_killtarget() {
  instrumentation->Kill();
}
