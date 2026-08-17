#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>

#include "srsran/common/crash_handler.h"
#include "srsran/srsran.h"

#include "ngscope/hdr/main.h"
#include "ngscope/hdr/dciLib/radio.h"
#include "ngscope/hdr/dciLib/task_scheduler.h"
#include "ngscope/hdr/dciLib/dci_decoder.h"
#include "ngscope/hdr/dciLib/load_config.h"
#include "ngscope/hdr/dciLib/ngscope_main.h"
#include "ngscope/hdr/dciLib/ngscope_rx.h"
// #include "ngscope/hdr/dciLib/asn_decoder.h"


const char* DEFAULT_CELLCFG_OUTPUT = "cell_cfg"; // global variable, default cell configuration output file
const char* DEFAULT_SIB_OUTPUT = "decoded_sibs"; // global variable, default sib output file
const char* DEFAULT_DCI_OUTPUT = "dci_output"; // global variable, default dci output file
const char* DEFAULT_OUTDIR = "ngscope_out";

bool go_exit = false; // global variable for signaling
bool have_sib1 = false; // global variable for sib1 decoding
bool have_sib2 = false; // global variable for sib2 decoding


/*********************************************
 * Function name: sig_int_handler
 * Return value type: void
 * Description: handle signal to modify the 
 *     global variable "go_exit".
 * Author: PAWS (https://paws.princeton.edu/)
*********************************************/
void sig_int_handler(int signo)
{
  printf("SIGINT received. Exiting...\n");

  if (signo == SIGINT) {
    go_exit = true;
  } else if (signo == SIGSEGV) {
    exit(1);
  }
}


/*********************************************
 * Function name: print_help
 * Return value type: void
 * Description: print help info for command 
 *     line inputs.
 * Author: PAWS (https://paws.princeton.edu/)
*********************************************/
void print_help()
{
  printf("NG-Scope usage: ngscope [OPTIONS]\n");
  printf("  -c <Config File>\t\t[Mandatory] NG-Scope configuration file.\n");
  printf("  -b <Cell Basic Configuration Output File>\t\t[Optional] Output file where the basic cell configuration information will be stored.\n");
  printf("  -s <SIB Output File>\t\t[Optional] Ouput file where the decoded SIB messages will be stored.\n");
  printf("  -o <DCI Output Folder>\t[Optional] Ouput folder where DCI logs will be stored.\n");
  printf("  -h\t\t\t\t[Optional] Show this menu.\n");
}


/*********************************************
 * Function name: main
 * Return value type: int
 * Description: the main function of ngscope,
 *     which takes command line inputs.
 * Author: PAWS (https://paws.princeton.edu/)
*********************************************/
int main(int argc, char** argv)
{
    ngscope_config_t config;
    int c;
    /* Variables tahtw ill hold the command line arguments */
    char* config_path = NULL;
    char* cellcfg_path = NULL;
    char* sib_path = NULL;
    char* out_path = NULL;

    /* Parsing command line arguments */
    while ((c = getopt (argc, argv, "c:s:b:o:h")) != -1) {
      switch (c) {
        case 'c':
          config_path = optarg;
          break;
        case 'b':
          cellcfg_path = optarg;
          break;
        case 's':
          sib_path = optarg;
          break;
        case 'o':
          out_path = optarg;
          break;
        case 'h':
          print_help();
          return 0;
        case '?':
          if (optopt == 'c') {
            fprintf (stderr, "Option -%c requires an argument.\n", optopt);
          }
          if (optopt == 'b') {
            fprintf (stderr, "Option -%c requires an argument.\n", optopt);
          }
          if (optopt == 's') {
            fprintf (stderr, "Option -%c requires an argument.\n", optopt);
          }
          if (optopt == 'o') {
            fprintf (stderr, "Option -%c requires an argument.\n", optopt);
          } else {
            print_help();
            return 1;
          }
        default:
          print_help();
          return 1;
        }
    }
    /* Check that the config file has been provided */
    if(config_path == NULL) {
      print_help();
      return 1;
    }
    printf("Configuration file: %s\n", config_path);
    /* Check SIB output */
    if(sib_path == NULL) {
      sib_path = DEFAULT_SIB_OUTPUT;
      printf("SIB output file not specified (using '%s')\n", sib_path);
    } else {
      printf("Decoded SIB file: %s\n", sib_path);
    }
    /* Check DCI output */
    if(out_path == NULL) {
      out_path = DEFAULT_OUTDIR;
      printf("DCI logs folder not specified (using '%s')\n", out_path);
    } else {
      printf("DCI logs folder: %s\n", out_path);
    }

    /* Signal handlers */
    srsran_debug_handle_crash(argc, argv);
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigprocmask(SIG_UNBLOCK, &sigset, NULL);
    signal(SIGINT, sig_int_handler);


    /* Load the configurations */
    ngscope_read_config(&config, config_path);
    /* Set DCI logs output folder path  */

    /* All three are bounded by OUT_PATH_MAX_LEN / SIB_LOGS_PATH_MAX_LEN, which is what the
     * prog_args buffers these are later strcpy'd into can hold. */
    char path[OUT_PATH_MAX_LEN];
    char dci_out_path[OUT_PATH_MAX_LEN];
    char sib_out_path[SIB_LOGS_PATH_MAX_LEN];
    char timestamp[32];

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);  // or gmtime(&now) for UTC

    strftime(timestamp, sizeof(timestamp), "%Y_%m_%d_%H_%M_%S", tm_info);

    /* Truncation here used to be silent, and produced a run directory with half a
     * timestamp in its name plus sibling "<partial>dci_output" directories. Refuse rather
     * than write the logs somewhere nobody asked for. */
    if ((size_t)snprintf(path, sizeof(path), "%s/%s/", out_path, timestamp) >= sizeof(path) ||
        (size_t)snprintf(dci_out_path, sizeof(dci_out_path), "%s%s/", path, DEFAULT_DCI_OUTPUT) >=
            sizeof(dci_out_path) ||
        (size_t)snprintf(sib_out_path, sizeof(sib_out_path), "%s%s/", path, DEFAULT_SIB_OUTPUT) >=
            sizeof(sib_out_path)) {
      fprintf(stderr,
              "Error: output path is too long (limit %d characters, including the timestamped "
              "run directory): %s\n",
              OUT_PATH_MAX_LEN,
              out_path);
      return 1;
    }

    int ret;
    ret = mkdir(out_path, 0755);
    if (ret < 0){
      if (errno != EEXIST){
        fprintf(stderr, "Error: Could not create %s\n", out_path);
        return 1;
      }
    }

    if (mkdir(path, 0755) < 0){
      fprintf(stderr, "Error: Could not create %s\n", path);
      return 1;
    }

    if (mkdir(dci_out_path, 0755) < 0){
      fprintf(stderr, "Error: Could not create %s\n", dci_out_path);
      return 1;
    }

    if (mkdir(sib_out_path, 0755) < 0){
      fprintf(stderr, "Error: Could not create %s\n", sib_out_path);
      return 1;
    }

    config.out_path = path;
    config.dci_logs_path = dci_out_path;
    config.sib_logs_path = sib_out_path;

    fprintf(stdout,"Using DCI Path: %s\n", config.dci_logs_path);
    fprintf(stdout,"Using SIB Path: %s\n", config.sib_logs_path);

    ngscope_main(&config);
    /* 0 = ran to completion. Every caller-visible failure above returns non-zero, so
     * `ngscope ... && <next step>` behaves the way a shell expects. */
    return 0;
}