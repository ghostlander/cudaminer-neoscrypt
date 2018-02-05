/**
 * Stats place holder
 *
 * Note: this source is C++ (requires std::map)
 *
 * tpruvot@github 2014
 */
#include <stdlib.h>
#include <memory.h>
#include <map>

#include "miner.h"
#include "log.h"

static std::map<uint64_t, stats_data> tlastscans;
static uint64_t uid = 0;

#define STATS_PURGE_TIMEOUT 120*60

extern uint64_t global_hashrate;
extern uint32_t opt_statsavg;

/**
 * Store speed per thread
 */
void stats_remember_speed(int thr_id, uint32_t hashcount, double hashrate,
  uint8_t found, uint32_t height) {
    const uint64_t key = uid++;
    stats_data data;

    if((hashcount < 1000) || (hashrate < 0.01))
      return;

    memset(&data, 0, sizeof(data));
    data.uid = (uint32_t) uid;
    data.gpu_id = (uint8_t) device_map[thr_id];
    data.thr_id = (uint8_t)thr_id;
    data.tm_stat = (uint32_t) time(NULL);
    data.height = height;
    data.hashcount = hashcount;
    data.hashfound = found;
    data.hashrate = hashrate;
    data.difficulty = global_diff;

    if((opt_n_threads == 1) && (global_hashrate && uid > 10)) {
        // prevent stats on too high vardiff (erroneous rates)
        double ratio = (hashrate / (1.0 * global_hashrate));
        if((ratio < 0.4) || (ratio > 1.6))
          data.ignored = 1;
    }

    tlastscans[key] = data;
}

/**
 * Get the computed average speed
 * @param thr_id int (-1 for all threads)
 */
double stats_get_speed(int thr_id, double def_speed) {
    double speed = 0.0;
    uint records = 0;

    std::map<uint64_t, stats_data>::reverse_iterator i = tlastscans.rbegin();
    while((i != tlastscans.rend()) && (records < opt_statsavg)) {
        if(!i->second.ignored && (thr_id == -1 || (i->second.thr_id == thr_id))) {
            if(i->second.hashcount > 1000) {
                speed += i->second.hashrate;
                records++;
            }
        }
        ++i;
    }

    if(records)
      speed /= (double)(records);
    else
      speed = def_speed;

    if(thr_id == -1)
      speed *= (double)(opt_n_threads);

    return(speed);
}

/**
 * Export data for api calls
 */
int stats_get_history(int thr_id, struct stats_data *data, int max_records) {
    int records = 0;

    std::map<uint64_t, stats_data>::reverse_iterator i = tlastscans.rbegin();
    while((i != tlastscans.rend()) && (records < max_records)) {
        if((!i->second.ignored) && (thr_id == -1 || (i->second.thr_id == thr_id))) {
            memcpy(&data[records], &(i->second), sizeof(struct stats_data));
            records++;
        }
        ++i;
    }

    return(records);
}

/**
 * Remove old entries to reduce memory usage
 */
void stats_purge_old(void) {
    int deleted = 0;
    uint32_t now = (uint32_t) time(NULL);
    uint sz = (uint)tlastscans.size();

    std::map<uint64_t, stats_data>::iterator i = tlastscans.begin();
    while(i != tlastscans.end()) {
        if(i->second.ignored || (now - i->second.tm_stat) > STATS_PURGE_TIMEOUT) {
            deleted++;
            tlastscans.erase(i++);
        } else ++i;
    }

    if(opt_debug && deleted)
      applog(LOG_DEBUG, "stats: %d/%d records purged", deleted, sz);
}

/**
 * Reset the cache
 */
void stats_purge_all(void)
{
	tlastscans.clear();
}

/**
 * API meminfo
 */
void stats_getmeminfo(uint64_t *mem, uint32_t *records)
{
	(*records) = (uint)tlastscans.size();
	(*mem) = (*records) * sizeof(stats_data);
}
