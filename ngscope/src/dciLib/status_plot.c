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
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

/* We force to use srsgui */
#ifdef ENABLE_GUI
#include "srsgui/srsgui.h"
#endif
#include "ngscope/hdr/dciLib/status_plot.h"
#include "ngscope/hdr/dciLib/time_stamp.h"

#define NOF_PLOT_SF 500
#define MOV_AVE_LEN 5

/****************************************************************************
 * Plot sink
 *
 * The same two series srsGUI draws -- the PDCCH equalized-symbol constellation and the
 * channel-response magnitude -- can instead be streamed to a listener over a unix socket,
 * so a front end can render them in its own window.
 *
 * Opt-in and side-effect free: the socket path comes from NGSCOPE_PLOT_SOCK, and with the
 * variable unset (anyone running ngscope from a terminal) nothing changes -- srsGUI opens
 * its windows exactly as before.
 *
 * Frames are little-endian host-order binary; producer and consumer are always the same
 * machine, since it is a unix socket.
 *
 *   uint32 magic 'NGP1'   uint32 seq   uint16 nof_const   uint16 nof_csi
 *   float  iq[2 * nof_const]           (I,Q interleaved, equalized PDCCH symbols)
 *   float  csi[nof_csi]                (channel response magnitude, dB)
 ****************************************************************************/
#define NGSCOPE_PLOT_MAGIC   0x3150474eu /* "NGP1" */
#define NGSCOPE_PLOT_MAX_FPS 20          /* srsGUI cannot draw 1000 subframes/s either */

static int plot_sink_connect(void)
{
    const char* path = getenv("NGSCOPE_PLOT_SOCK");
    if (path == NULL || path[0] == '\0') {
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("plot: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("plot: cannot connect to %s: %s -- falling back to srsGUI\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    printf("plot: streaming PDCCH symbols and channel response to %s\n", path);
    return fd;
}

/* Returns 0 on success, -1 once the peer has gone away. */
static int plot_sink_write(int fd, const void* buf, size_t len)
{
    const uint8_t* p = (const uint8_t*)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n > 0) {
            p += n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EINTR)) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int plot_sink_send(int fd, uint32_t seq, const cf_t* iq, int nof_const, const float* csi, int nof_csi)
{
    uint32_t header[2] = {NGSCOPE_PLOT_MAGIC, seq};
    uint16_t counts[2] = {(uint16_t)nof_const, (uint16_t)nof_csi};

    if (plot_sink_write(fd, header, sizeof(header)) < 0 ||
        plot_sink_write(fd, counts, sizeof(counts)) < 0) {
        return -1;
    }
    /* cf_t is a complex float: contiguous (I,Q) pairs, so it goes out as-is. */
    if (nof_const > 0 && plot_sink_write(fd, iq, (size_t)nof_const * 2 * sizeof(float)) < 0) {
        return -1;
    }
    if (nof_csi > 0 && plot_sink_write(fd, csi, (size_t)nof_csi * sizeof(float)) < 0) {
        return -1;
    }
    return 0;
}
extern bool go_exit;
extern pthread_mutex_t     plot_mutex;
extern ngscope_plot_t      plot_data;
extern pthread_cond_t      plot_cond;

extern pthread_mutex_t dci_plot_mutex;
extern cf_t* pdcch_buf;
extern float csi_amp[110 * 15 * 2048];
extern pthread_cond_t 	dci_plot_cond;
//	
//void init_plot_data(ngscope_CA_status_t* q, int nof_dev){
//    pthread_mutex_lock(&plot_mutex);
//    plot_data.nof_cell = nof_dev;
//
//    //pthread_mutex_lock(&cell_mutex);
//    for(int i=0; i<nof_dev; i++){
//        plot_data.cell_prb[i] = q->cell_prb[i];
//    }
//    //pthread_mutex_unlock(&cell_mutex);
//
//    pthread_mutex_unlock(&plot_mutex);
//}
int sum_per_sf_prb_dl(ngscope_dci_per_sub_t* q){
    int nof_dl_prb = 0;
    if(q->nof_dl_dci > 0){
        for(int i=0; i< q->nof_dl_dci; i++){
            nof_dl_prb += q->dl_msg[i].prb; 
        }
    }
    return nof_dl_prb;
}

int sum_per_sf_prb_ul(ngscope_dci_per_sub_t* q){
    int nof_ul_prb = 0;
    if(q->nof_ul_dci > 0){
        for(int i=0; i< q->nof_ul_dci; i++){
            nof_ul_prb += q->ul_msg[i].prb; 
        }
    }
    return nof_ul_prb;
}

int status_tracker_handle_plot(ngscope_status_buffer_t* dci_buffer){
    int      idx, max_prb;
    uint32_t tti = dci_buffer->tti;
    int cell_idx = dci_buffer->cell_idx;

    idx = tti % PLOT_SF;
    pthread_mutex_lock(&plot_mutex);
    max_prb = plot_data.cell_prb[cell_idx];
        
    /* Enqueue CSI */
    for(int i=0; i< max_prb * 12; i++){
        //plot_data.plot_data_cell[cell_idx].plot_data_sf[idx].csi_amp[i] = \
            dci_buffer->csi_amp[i];
    }

    /* Enqueue TTI */
    plot_data.plot_data_cell[cell_idx].plot_data_sf[idx].tti = tti;

    /* Enqueue Cell downlink PRB */
    plot_data.plot_data_cell[cell_idx].plot_data_sf[idx].cell_dl_prb = 
        sum_per_sf_prb_dl(&dci_buffer->dci_per_sub);

    /* Enqueue Cell uplink PRB */
    plot_data.plot_data_cell[cell_idx].plot_data_sf[idx].cell_ul_prb = 
        sum_per_sf_prb_ul(&dci_buffer->dci_per_sub);

    /* touch the buffer and set the token */ 
    plot_data.plot_data_cell[cell_idx].dci_touched = idx;
    plot_data.plot_data_cell[cell_idx].token[idx]  = 1;

    pthread_cond_signal(&plot_cond);
    pthread_mutex_unlock(&plot_mutex);

    return 0;
}



uint16_t contineous_handled_sf(ngscope_plot_cell_t* q){
    uint16_t start  = q->header;
    uint16_t end    = q->dci_touched;
    uint16_t untouched_idx;

    // init the untouched index
    untouched_idx = start;

    // No change return
    if( end == start)
        return start;

    // unwrapping
    if( end < start){ end += PLOT_SF;}

    for(int i=start+1;i<=end;i++){
        uint16_t index = i % PLOT_SF;
        untouched_idx = i;
        if(q->token[index] == 0){
            // return when we encounter a token that has been taken
            untouched_idx -= 1;
            return  untouched_idx % PLOT_SF;
        }
    }
    return  untouched_idx % PLOT_SF;
}

int movingAvg(int *ptrArrNumbers, int *ptrSum, int pos, int len, int nextNum)
{
  //Subtract the oldest number from the prev sum, add the new number
  *ptrSum = *ptrSum - ptrArrNumbers[pos] + nextNum;
  //Assign the nextNum to the position in the array
  ptrArrNumbers[pos] = nextNum;
  //return the average
  return *ptrSum / len;
}


void left_shift_vec(float* vec){
    for(int i=0; i< NOF_PLOT_SF-1; i++){
        vec[i] = vec[i+1];
    }
    return;
}



void* plot_thread_run(void* arg)
{

#ifdef ENABLE_GUI
    int nof_prb;
    int nof_sub;

    nof_prb = plot_data.cell_prb[0];
    nof_sub = 12 * nof_prb;
 
    sdrgui_init();
    //plot_real_t csi;
    plot_real_t p_prb_ul, p_prb_dl;
//    plot_scatter_t pdsch, pdcch;
    plot_waterfall_t csi_water;

    plot_waterfall_init(&csi_water, nof_sub, 100);
    plot_waterfall_setTitle(&csi_water, "Channel Response - Magnitude");
    plot_complex_setPlotXLabel(&csi_water, "Subcarrier Index"); 
    plot_complex_setPlotYLabel(&csi_water, "dB"); 
    plot_waterfall_setSpectrogramXLabel(&csi_water, "Subcarrier Index"); 
    plot_waterfall_setSpectrogramYLabel(&csi_water, "Time"); 

//    plot_scatter_init(&pdsch);
//    plot_scatter_setTitle(&pdsch, "PDSCH - Equalized Symbols");
//    plot_scatter_setXAxisScale(&pdsch, -4, 4);
//    plot_scatter_setYAxisScale(&pdsch, -4, 4);
//    plot_scatter_addToWindowGrid(&pdsch, (char*)"pdsch_ue", 0, 0);
//        
//    plot_scatter_init(&pdcch);
//    plot_scatter_setTitle(&pdcch, "PDCCH - Equalized Symbols");
//    plot_scatter_setXAxisScale(&pdcch, -4, 4);
//    plot_scatter_setYAxisScale(&pdcch, -4, 4);
//    plot_real_addToWindowGrid(&pdcch, (char*)"pdsch_ue", 0, 1);

//    plot_real_init(&csi);
//    plot_real_setTitle(&csi, "Channel Response - Magnitude");
//    plot_real_setLabels(&csi, "Subcarrier Index", "dB");
//    plot_real_setYAxisScale(&csi, -40, 40);
//    plot_real_addToWindowGrid(&csi, (char*)"pdsch_ue", 0, 1);

    plot_real_init(&p_prb_dl);
    plot_real_setTitle(&p_prb_dl, "Downlink PRB usage");
    plot_real_setLabels(&p_prb_dl, "Time", "PRB");
    plot_real_setYAxisScale(&p_prb_dl, 0, nof_prb);
    plot_real_addToWindowGrid(&p_prb_dl, (char*)"pdsch_ue", 0, 0);

    plot_real_init(&p_prb_ul);
    plot_real_setTitle(&p_prb_ul, "Uplink PRB usage");
    plot_real_setLabels(&p_prb_ul, "Time", "PRB");
    plot_real_setYAxisScale(&p_prb_ul, 0, nof_prb);
    plot_real_addToWindowGrid(&p_prb_ul, (char*)"pdsch_ue", 1, 0);

    int prb_idx = 0;
    float cell_dl_prb[NOF_PLOT_SF] = {0};
    float cell_ul_prb[NOF_PLOT_SF] = {0};
    float cell_dl_prb_ave[NOF_PLOT_SF] = {0};
    float cell_ul_prb_ave[NOF_PLOT_SF] = {0};
 
    int mv_ave_buf_dl[MOV_AVE_LEN] = {0};
    int mv_ave_buf_ul[MOV_AVE_LEN] = {0};

    int sum_dl = 0;
    int sum_ul = 0;

    while(!go_exit){
        pthread_mutex_lock(&plot_mutex);    
        pthread_cond_wait(&plot_cond, &plot_mutex); 

        int ave_idx = 0;
        /* Plot the data */
        uint16_t new_header     = contineous_handled_sf(&plot_data.plot_data_cell[0]);
        uint16_t last_header    = plot_data.plot_data_cell[0].header;
        if( new_header != last_header){
            plot_data.plot_data_cell[0].header = new_header;
            if(new_header < last_header){ new_header += PLOT_SF;}
            //printf("now Update header: ->>>>> last header:%d new header:%d\n", last_header, new_header);
            for(int i = last_header+1; i<= new_header; i++){
                uint16_t index = i % PLOT_SF;
                float* csi_amp = plot_data.plot_data_cell[0].plot_data_sf[index].csi_amp;
                //plot_real_setNewData(&csi, csi_amp, nof_sub); 
                plot_waterfall_appendNewData(&csi_water, csi_amp, nof_sub); 
                plot_data.plot_data_cell[0].token[index] = 0;
                uint32_t tti =  plot_data.plot_data_cell[0].plot_data_sf[index].tti;
                printf("plot_thread -> tti:%d\n", tti);
                int dl_prb = plot_data.plot_data_cell[0].plot_data_sf[index].cell_dl_prb;
                int ul_prb = plot_data.plot_data_cell[0].plot_data_sf[index].cell_ul_prb;
                // plot PRB usage
                if(prb_idx < NOF_PLOT_SF){
                    cell_dl_prb[prb_idx] = (float)dl_prb; 
                    cell_ul_prb[prb_idx] = (float)ul_prb; 
                    
                    cell_dl_prb_ave[prb_idx] = (float)movingAvg(mv_ave_buf_dl, &sum_dl, ave_idx, MOV_AVE_LEN, dl_prb); 
                    cell_ul_prb_ave[prb_idx] = (float)movingAvg(mv_ave_buf_ul, &sum_ul, ave_idx, MOV_AVE_LEN, ul_prb); 
                    ave_idx++;
                    if(ave_idx >= MOV_AVE_LEN){ ave_idx = 0;}

                    prb_idx++;
                }else{
                    left_shift_vec(cell_dl_prb);
                    left_shift_vec(cell_ul_prb);

                    left_shift_vec(cell_dl_prb_ave);
                    left_shift_vec(cell_ul_prb_ave);


                    cell_dl_prb[NOF_PLOT_SF-1] = (float)dl_prb; 
                    cell_ul_prb[NOF_PLOT_SF-1] = (float)ul_prb; 

                    cell_dl_prb_ave[NOF_PLOT_SF-1] = (float)movingAvg(mv_ave_buf_dl, &sum_dl, ave_idx, MOV_AVE_LEN, dl_prb); 
                    cell_ul_prb_ave[NOF_PLOT_SF-1] = (float)movingAvg(mv_ave_buf_ul, &sum_ul, ave_idx, MOV_AVE_LEN, ul_prb); 

                    ave_idx++;
                    if(ave_idx >= MOV_AVE_LEN){ ave_idx = 0;}
                }
                
                //plot_real_setNewData(&p_prb_dl, cell_dl_prb, NOF_PLOT_SF); 
                //plot_real_setNewData(&p_prb_ul, cell_ul_prb, NOF_PLOT_SF); 
 
                plot_real_setNewData(&p_prb_dl, cell_dl_prb_ave, NOF_PLOT_SF); 
                plot_real_setNewData(&p_prb_ul, cell_ul_prb_ave, NOF_PLOT_SF); 
            }
        } 
        pthread_mutex_unlock(&plot_mutex);    
    }
#endif
    return NULL;
}
void  plot_init_thread(pthread_t* plot_thread){
    pthread_attr_t     attr;
    struct sched_param param;
    param.sched_priority = 0;
    pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
    pthread_attr_setschedparam(&attr, &param);
    if (pthread_create(plot_thread, NULL, plot_thread_run, NULL)) {
        perror("pthread_create");
        exit(-1);
    }
    return;
}

void* plot_pdcch_run(void* arg)
{
#ifdef ENABLE_GUI
	printf("init 0!\n");
	decoder_plot_t* q = (decoder_plot_t*)arg;
	//int decoder_idx 		= q->decoder_idx; 
	int nof_pdcch_sample 	= q->nof_pdcch_sample;
	int size 				= q->size;

    plot_scatter_t pdcch;
    plot_real_t csi;

    /* NGSCOPE_PLOT_SOCK routes the same two series to a front end instead of opening
     * srsGUI's own windows. Unset -> unchanged behaviour. */
    int sink = plot_sink_connect();

    if (sink < 0) {
        sdrgui_init();

        plot_scatter_init(&pdcch);
        plot_scatter_setTitle(&pdcch, "PDCCH - Equalized Symbols");
        plot_scatter_setXAxisScale(&pdcch, -3, 3);
        plot_scatter_setYAxisScale(&pdcch, -3, 3);

        plot_real_addToWindowGrid(&pdcch, (char*)"pdsch_ue", 0, 0);

        plot_real_init(&csi);
        plot_real_setTitle(&csi, "Channel Response - Magnitude");
        plot_real_setLabels(&csi, "Subcarrier Index", "dB");
        plot_real_setYAxisScale(&csi, -40, 40);
        plot_real_addToWindowGrid(&csi, (char*)"pdsch_ue", 0, 1);
    }

    /* Snapshot buffers: the socket write must not happen under dci_plot_mutex, or a slow
     * reader would stall the decoder thread that signals us. */
    cf_t*  iq_snapshot  = NULL;
    float* csi_snapshot = NULL;
    if (sink >= 0) {
        iq_snapshot  = srsran_vec_cf_malloc(nof_pdcch_sample > 0 ? nof_pdcch_sample : 1);
        csi_snapshot = srsran_vec_f_malloc(size > 0 ? size : 1);
        if (iq_snapshot == NULL || csi_snapshot == NULL) {
            printf("plot: out of memory for snapshot buffers\n");
            close(sink);
            sink = -1;
        }
    }

    uint32_t seq          = 0;
    int64_t  next_frame_us = 0;

    while(!go_exit){
        pthread_mutex_lock(&dci_plot_mutex);
		//printf("waiting for signal!\n");
        pthread_cond_wait(&dci_plot_cond, &dci_plot_mutex);

        if (sink >= 0) {
            /* Decoding runs at 1000 subframes/s; nothing can usefully draw that fast, so
             * drop frames rather than queue them and fall behind. */
            int64_t now = timestamp_us();
            if (now < next_frame_us) {
                pthread_mutex_unlock(&dci_plot_mutex);
                continue;
            }
            next_frame_us = now + 1000000 / NGSCOPE_PLOT_MAX_FPS;

            memcpy(iq_snapshot, pdcch_buf, (size_t)nof_pdcch_sample * sizeof(cf_t));
            memcpy(csi_snapshot, csi_amp, (size_t)size * sizeof(float));
            pthread_mutex_unlock(&dci_plot_mutex);

            if (plot_sink_send(sink, seq++, iq_snapshot, nof_pdcch_sample, csi_snapshot, size) < 0) {
                printf("plot: listener closed the connection, stopping plot stream\n");
                close(sink);
                sink = -1;
            }
            continue;
        }

      	plot_scatter_setNewData(&pdcch, pdcch_buf, nof_pdcch_sample);
      	plot_real_setNewData(&csi, csi_amp, size);
        pthread_mutex_unlock(&dci_plot_mutex);
	}

    if (sink >= 0) {
        close(sink);
    }
    free(iq_snapshot);
    free(csi_snapshot);
#endif

	return NULL;
}


void plot_init_pdcch_thread(pthread_t* plot_thread, decoder_plot_t* arg){
    pthread_attr_t     attr;
    struct sched_param param;
    param.sched_priority = 0;
    pthread_attr_init(&attr);
    pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
    pthread_attr_setschedparam(&attr, &param);
	printf("plot thread creating thread!\n");
    if (pthread_create(plot_thread, NULL, plot_pdcch_run, (void *)arg)) {
        perror("pthread_create");
        exit(-1);
    }
    return;
}
