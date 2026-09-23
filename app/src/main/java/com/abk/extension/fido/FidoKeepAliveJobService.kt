package com.abk.extension.fido

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context

class FidoKeepAliveJobService : JobService() {
    override fun onStartJob(params: JobParameters?): Boolean {
        // The keep-alive job can fire while the app is in the background, where a
        // foreground-service start is disallowed; requestSync tolerates that
        // instead of letting the exception crash the job's process.
        FidoSyncService.requestSync(this, "job_keepalive")
        jobFinished(params, false)
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean = false

    companion object {
        private const val JOB_ID = 0xA8F1D0

        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            val component = ComponentName(context, FidoKeepAliveJobService::class.java)
            val info = JobInfo.Builder(JOB_ID, component)
                .setPersisted(true)
                .setPeriodic(15 * 60 * 1000L)
                .build()
            scheduler.schedule(info)
        }
    }
}
