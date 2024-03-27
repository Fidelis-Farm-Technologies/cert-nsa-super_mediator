/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_stat.c
 *
 *  Handles mediator/yaf stats
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  Super Mediator 2.0.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2321
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */

#include "mediator_inf.h"
#include "mediator_core.h"
#include "mediator_util.h"
#include "mediator_stat.h"
#include "mediator_structs.h"

static GTimer *md_start = NULL;

/**
 * mdStatInit
 *
 *
 *
 */
void
mdStatInit(
    void)
{
    md_start = g_timer_new();
    g_timer_start(md_start);
}


/**
 * mdStatGetTimer
 *
 *
 */
GTimer *
mdStatGetTimer(
    void)
{
    return md_start;
}


/**
 *   Fills `buffer` with a string "1d:2h:4m:8s" based on the value of `uptime`,
 *   an integer number giving a number of elapsed seconds.
 *
 *   If `uptime` is 0 or negative, fills `buffer` with "0d:0h:0m:0s".
 *
 *   Parameter `buflen` is the length of `buffer`.
 *
 *   Returns the number of bytes that were (or would have been) written to
 *   `buffer` (not including the terminating NULL) assuming it is large enough
 *   to hold the result.
 */
static ssize_t
mdUptimeToString(
    char       *buffer,
    size_t      buflen,
    int64_t     uptime)
{
    lldiv_t days;
    lldiv_t hours;
    lldiv_t mins;

    if (uptime <= 0) {
        return snprintf(buffer, buflen, "0d:0h:0m:0s");
    }

    days  = lldiv((long long)uptime, 86400);
    hours = lldiv(days.rem, 3600);
    mins  = lldiv(hours.rem, 60);

    return snprintf(buffer, buflen, "%lldd:%lldh:%lldm:%llds",
                    days.quot, hours.quot, mins.quot, mins.rem);
}



/**
 * mdLogStats
 *
 * Log YAF process statistics
 *
 */
void
mdStatLogYAFStats(
    mdGenericRec_t     *mdRec)
{
    yafStatsV1Rec_t        *statsV1 = NULL;
    yafStatsV2Rec_t        *statsV2 = NULL;
    mdYafStatsTmplCtx_t    *intTmplCtx =
                                    (mdYafStatsTmplCtx_t*)mdRec->intTmplCtx;
    GString                *tcString = NULL;
    char ipaddr[20];
    char uptime[1024];

    memset(ipaddr, 0, sizeof(ipaddr));

    switch (intTmplCtx->defCtx.templateContents.specCase.yafStats) {
      case TC_YAF_STATS_V1:
        statsV1 = (yafStatsV1Rec_t*)mdRec->fbRec->rec;

        md_util_print_ip4_addr(ipaddr, statsV1->exporterIPv4Address);

        /* uptime is the difference from system init time to NOW */
        mdUptimeToString(uptime, sizeof(uptime) - 1,
                         (time(NULL)
                          - (statsV1->systemInitTimeMilliseconds / 1000)));

        g_message("%s: YAF V1 Stats - Observation Domain: %" PRIu32
                  " IP: %s Uptime: %s",
                  mdRec->collector->name, statsV1->exportingProcessId,
                  ipaddr, uptime);
        g_message("%s: "
                  "YAF Flows: %" PRIu64
                  " Packets: %" PRIu64
                  " Dropped: %" PRIu64
                  " Ignored: %" PRIu64
                  " Out of Sequence: %" PRIu64
                  " Expired Frags: %u"
                  " Assembled Frags: %u"
                  " Flow Table Flush Events: %u"
                  " Flow Table Peak Count %u"
                  " Mean Flow Rate %u"
                  " Mean Packet Rate %u",
                  mdRec->collector->name,
                  statsV1->exportedFlowRecordTotalCount,
                  statsV1->packetTotalCount,
                  statsV1->droppedPacketTotalCount,
                  statsV1->ignoredPacketTotalCount,
                  statsV1->notSentPacketTotalCount,
                  statsV1->yafExpiredFragmentCount,
                  statsV1->yafAssembledFragmentCount,
                  statsV1->yafFlowTableFlushEventCount,
                  statsV1->yafFlowTablePeakCount,
                  statsV1->yafMeanFlowRate,
                  statsV1->yafMeanPacketRate);
        break;

      case TC_YAF_STATS_V2:
      case TC_YAF_STATS_V2_SCOPE2:
        statsV2 = (yafStatsV2Rec_t*)mdRec->fbRec->rec;

        /* uptime is the difference from system init time to the observation
         * time */
        mdUptimeToString(uptime, sizeof(uptime) - 1,
                         (statsV2->observationTimeSeconds
                          - (statsV2->systemInitTimeMilliseconds / 1000)));

        md_util_print_ip4_addr(ipaddr, statsV2->exporterIPv4Address);

        g_message("%s: YAF V2 Stats - Observation Domain: %" PRIu32
                  " IP: %s PID: %" PRIu32 " Uptime: %s",
                  mdRec->collector->name, statsV2->observationDomainId,
                  ipaddr, statsV2->exportingProcessId, uptime);
        g_message("%s:"
                  " YAF Flows: %" PRIu64
                  " Packets: %" PRIu64
                  " Dropped: %" PRIu64
                  " Ignored: %" PRIu64
                  " Out of Sequence: %" PRIu64
                  " Expired Frags: %u"
                  " Assembled Frags: %u"
                  " Flow Table Flush Events: %u"
                  " Flow Table Peak Count %u"
                  " Mean Flow Rate %u"
                  " Mean Packet Rate %u",
                  mdRec->collector->name,
                  statsV2->exportedFlowRecordTotalCount,
                  statsV2->packetTotalCount,
                  statsV2->droppedPacketTotalCount,
                  statsV2->ignoredPacketTotalCount,
                  statsV2->notSentPacketTotalCount,
                  statsV2->yafExpiredFragmentCount,
                  statsV2->yafAssembledFragmentCount,
                  statsV2->yafFlowTableFlushEventCount,
                  statsV2->yafFlowTablePeakCount,
                  statsV2->yafMeanFlowRate,
                  statsV2->yafMeanPacketRate);
        break;

      default:
        tcString =
            mdUtilDebugTemplateContents(intTmplCtx->defCtx.templateContents);
        g_warning("unknown stats version %s", tcString->str);
        g_string_free(tcString, TRUE);
        break;
    }
}

void
mdStatLogAllStats(
    mdContext_t    *ctx)
{
    mdStatGetCollectorSummary(ctx);
    mdStatGetExporterSummary(ctx);

    mdStatLogOverall(ctx);
    mdStatLogCollectors(ctx);
    mdStatLogCore(ctx);
    mdStatLogExporters(ctx);

    mdStatSanityCheck(ctx);
}

#define STAT_UPDATE_COL_STAT(__stat__)                                      \
    colSum->__stat__ += thisColStats->__stat__;

void
mdStatGetCollectorSummary(
    mdContext_t    *ctx)
{
    mdConfig_t         *cfg             = ctx->cfg;
    mdColStats_t       *colSum          = &ctx->colSummary;
    mdCollector_t      *col             = NULL;
    mdColStats_t       *thisColStats    = NULL;
    uint16_t            i;

    memset(colSum, 0, sizeof(mdColStats_t));

    for (col = cfg->firstCol; col; col = col->next) {
        thisColStats = &col->colStats;

        thisColStats->totalRecordsRead = 0;

        for (i = 1; i < TC_NUM_TYPES; i++) {
            thisColStats->totalRecordsRead +=
                thisColStats->recordsReadByType[i];
            STAT_UPDATE_COL_STAT(recordsReadByType[i]);
            STAT_UPDATE_COL_STAT(recordsFilteredOutByType[i]);
        }

        STAT_UPDATE_COL_STAT(filesRead);
    /* need to get all bytes read, not just top level to work */
/*        STAT_UPDATE_COL_STAT(bytesRead);*/
        STAT_UPDATE_COL_STAT(restarts);
        STAT_UPDATE_COL_STAT(totalRecordsRead);
    }
}

#define STAT_UPDATE_EXP_STAT(__stat__)                                      \
    expSum->__stat__ += thisExpStats->__stat__;

void
mdStatGetExporterSummary(
    mdContext_t    *ctx)
{
    mdConfig_t         *cfg             = ctx->cfg;
    mdExpStats_t         *expSum          = &ctx->expSummary;
    mdExporter_t       *exp             = NULL;
    mdExpStats_t         *thisExpStats    = NULL;
    uint16_t            i;

    memset(expSum, 0, sizeof(mdExpStats_t));

    for (exp = cfg->firstExp; exp; exp = exp->next) {
        thisExpStats = &exp->expStats;

        thisExpStats->totalRecordsWritten = 0;

        for (i = 1; i < TC_NUM_TYPES; i++) {
            thisExpStats->totalRecordsWritten +=
                (thisExpStats->recordsForwardedByType[i] +
                 thisExpStats->recordsGeneratedByType[i]);
            STAT_UPDATE_EXP_STAT(recordsIgnoredByType[i]);
            STAT_UPDATE_EXP_STAT(recordsFilteredOutByType[i]);
            STAT_UPDATE_EXP_STAT(recordsGeneratedByType[i]);
            STAT_UPDATE_EXP_STAT(recordsForwardedByType[i]);
        }

        STAT_UPDATE_EXP_STAT(totalRecordsWritten);

        STAT_UPDATE_EXP_STAT(filesWritten);
        STAT_UPDATE_EXP_STAT(bytesWritten);
        STAT_UPDATE_EXP_STAT(restarts);

        for (i = 0; i < UINT16_MAX; i++) {
            STAT_UPDATE_EXP_STAT(flowsByAppLabel[i]);
        }
    }
}

void
mdStatLogOverall(
    mdContext_t    *ctx)
{
    GString            *ovrString   = g_string_sized_new(1024);
    mdColStats_t       *colSummary  = &ctx->colSummary;
    mdExpStats_t       *expSummary  = &ctx->expSummary;
    mdUtilTCGeneral_t   i;
    char                uptime[1024];

    /* uptime is the elapsed time of the GTimer */
    mdUptimeToString(uptime, sizeof(uptime) - 1,
                     g_timer_elapsed(md_start, NULL));

    g_string_append_printf(
        ovrString, "Overall Stats: Uptime: %s, ",
        uptime);
    g_string_append_printf(
        ovrString, "Total Records Read: %" PRIu64 ", ",
        colSummary->totalRecordsRead);
    g_string_append_printf(
        ovrString, "Total Records Written: %" PRIu64 ", ",
        expSummary->totalRecordsWritten);
    g_string_append_printf(
        ovrString, "Total Files Read: %" PRIu32 ", ",
        colSummary->filesRead);
    g_string_append_printf(
        ovrString, "Total Files Written: %" PRIu32 ", ",
        expSummary->filesWritten);
    g_string_append_printf(
        ovrString, "Total Bytes Written: %" PRIu64 ", ",
        expSummary->bytesWritten);

    for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
        if (expSummary->recordsForwardedByType[i]) {
            g_string_append_printf(
                ovrString, "Total %s Records Forwarded: %" PRIu64 ", ",
                mdUtilDebugTemplateContentsGeneral(i),
                expSummary->recordsForwardedByType[i]);
        }
    }

    for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
        if (expSummary->recordsGeneratedByType[i]) {
            g_string_append_printf(
                ovrString, "Total %s Records Generated: %" PRIu64 ", ",
                mdUtilDebugTemplateContentsGeneral(i),
                expSummary->recordsGeneratedByType[i]);
        }
    }

    pthread_mutex_lock(&(md_config.log_mutex));
    g_message("%s", ovrString->str);
    pthread_mutex_unlock(&(md_config.log_mutex));

    g_string_free(ovrString, TRUE);
}

void
mdStatLogCollectors(
    mdContext_t    *ctx)
{
    mdConfig_t     *cfg     = ctx->cfg;
    /* mdColStats_t   *colSum  = &ctx->colSummary;  FIXME: Remove? */

    mdCollector_t      *collector;
    GString            *colString;
    mdUtilTCGeneral_t   i;

    colString = g_string_sized_new(1024);

    for (collector = cfg->firstCol; collector; collector = collector->next) {
        g_string_truncate(colString, 0);

        g_string_append_printf(
            colString, "Collector Stats: %s-%s-%s: ",
            collector->name,
            ((collector->active) ? "ACTIVE" : "INACTIVE"),
            mdUtilDebugCollectionMethod(collector->collectionMethod));
        g_string_append_printf(
            colString, "Total Records Read: %" PRIu64 ", ",
            collector->colStats.totalRecordsRead);
        g_string_append_printf(
            colString, "Files Read: %" PRIu32 ", ",
            collector->colStats.filesRead);
    /* need to get all bytes read, not just top level */
/*        g_string_append_printf(colString, "Bytes Read: %" PRIu64 ", ",
                                    collector->colStats.bytesRead);*/
        g_string_append_printf(
            colString, "Restarts: %" PRIu16 ", ",
            collector->colStats.restarts);

        for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
            g_string_append_printf(
                colString, "%s Records: %" PRIu64 ", ",
                mdUtilDebugTemplateContentsGeneral(i),
                collector->colStats.recordsReadByType[i]);
        }

        /* only print the filter counts if using a file */
        if (NULL == collector->filter) {
            g_string_append(colString, "No filters used");
        } else {
            for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
                g_string_append_printf(
                    colString, "%s Filtered: %" PRIu64 ", ",
                    mdUtilDebugTemplateContentsGeneral(i),
                    collector->colStats.recordsFilteredOutByType[i]);
            }
        }

        pthread_mutex_lock(&(cfg->log_mutex));

        g_message("%s", colString->str);

        pthread_mutex_unlock(&(cfg->log_mutex));
    }

    g_string_free(colString, TRUE);
}

void
mdStatLogCore(
    mdContext_t    *ctx)
{
    mdConfig_t         *cfg         = ctx->cfg;
    mdCoreStats_t      *coreStats   = &ctx->coreStats;
    GString            *coreString  = g_string_sized_new(1024);
    mdUtilTCGeneral_t   i;
    uint64_t            totalRecordsProcessed = 0;

    for (i = 0; i < TC_NUM_TYPES; i++) {
        totalRecordsProcessed += coreStats->recordsProcessedByType[i];
    }

    g_string_append(coreString, "Core Stats: ");
    g_string_append_printf(
        coreString, "Records Processed: %" PRIu64 ", ",
        totalRecordsProcessed);
/*    g_string_append_printf(coreString, "Bytes Processed: %" PRIu64 ", ",
                            coreStats->bytesProcessed);*/

    for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
        g_string_append_printf(
            coreString, "%s Records: %" PRIu64 ", ",
            mdUtilDebugTemplateContentsGeneral(i),
            coreStats->recordsProcessedByType[i]);
    }

    for (i = 0; i < UINT16_MAX; i++) {
        if (coreStats->flowsByAppLabel[i]) {
          g_string_append_printf(
              coreString, "AppLabel %d Records: %" PRIu64 ", ",
              i, coreStats->flowsByAppLabel[i]);
        }
    }

    g_string_append_printf(
        coreString, "Tombstone Records Generated: %" PRIu64,
        coreStats->tombstoneRecordsGenerated);

    pthread_mutex_lock(&(cfg->log_mutex));
    g_message("%s", coreString->str);
    pthread_mutex_unlock(&(cfg->log_mutex));

    g_string_free(coreString, TRUE);
}

void
mdStatLogExporters(
    mdContext_t    *ctx)
{
    mdConfig_t         *cfg         = ctx->cfg;
    /* mdExpStats_t         *expSum      = &ctx->expSummary; FIXME: Remove? */

    mdExporter_t       *exporter;
    GString            *expString;
    mdUtilTCGeneral_t   i;
    uint16_t            a;

    expString = g_string_sized_new(1536);

    for (exporter = cfg->firstExp; exporter; exporter = exporter->next) {
        g_string_truncate(expString, 0);

        g_string_append_printf(
            expString, "Exporter Stats: %s-%s-%s: ",
            exporter->name,
            ((exporter->active) ? "ACTIVE" : "INACTIVE"),
            mdUtilDebugExportMethod(exporter->exportMethod));
        g_string_append_printf(
            expString, "Total Records Written: %" PRIu64 ", ",
            exporter->expStats.totalRecordsWritten);
        g_string_append_printf(
            expString, "Files Written: %" PRIu32 ", ",
            exporter->expStats.filesWritten);
        g_string_append_printf(
            expString, "Bytes Written: %" PRIu64 ", ",
            exporter->expStats.bytesWritten);
        g_string_append_printf(
            expString, "Restarts: %" PRIu16 ", ",
            exporter->expStats.restarts);

        if (NULL == exporter->filter) {
            g_string_append(expString, "No filters used, ");
        } else {
            for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
                g_string_append_printf(
                    expString, "%s Filtered: %" PRIu64 ", ",
                    mdUtilDebugTemplateContentsGeneral(i),
                    exporter->expStats.recordsFilteredOutByType[i]);
            }
        }

        for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
            g_string_append_printf(
                expString, "%s Ignored: %" PRIu64 ", ",
                mdUtilDebugTemplateContentsGeneral(i),
                exporter->expStats.recordsIgnoredByType[i]);
        }

        for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
            g_string_append_printf(
                expString, "%s Generated: %" PRIu64 ", ",
                mdUtilDebugTemplateContentsGeneral(i),
                exporter->expStats.recordsGeneratedByType[i]);
        }

        for (i = TC_UNKNOWN; i < TC_NUM_TYPES; i++) {
            g_string_append_printf(
                expString, "%s Forwarded: %" PRIu64 ", ",
                mdUtilDebugTemplateContentsGeneral(i),
                exporter->expStats.recordsForwardedByType[i]);
        }

        for (a = 0; a < UINT16_MAX; a++) {
            if (exporter->expStats.flowsByAppLabel[a]) {
                g_string_append_printf(
                    expString, "AppLabel %d Records: %" PRIu64 ", ",
                    a, exporter->expStats.flowsByAppLabel[a]);
            }
        }

        pthread_mutex_lock(&(cfg->log_mutex));
        g_message("%s", expString->str);
        pthread_mutex_unlock(&(cfg->log_mutex));
    }

    g_string_free(expString, TRUE);
}

void
mdStatSanityCheck(
    mdContext_t    *ctx)
{
    /* mdCoreStats_t  *coreStats   = &ctx->coreStats; */
    /* mdExpStats_t   *expSum      = &ctx->expSummary; */
    /* mdColStats_t   *colSum      = &ctx->colSummary; */
    /* mdConfig_t     *cfg         = ctx->cfg; */
    /* mdExporter_t   *exp; */

    MD_UNUSED_PARAM(ctx);
}

