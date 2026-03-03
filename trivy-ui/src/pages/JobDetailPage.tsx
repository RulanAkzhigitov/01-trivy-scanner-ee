import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { JobWithResults, fetchJob } from '@/lib/api';
import { toast } from 'sonner';

export function JobDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [job, setJob] = useState<JobWithResults | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    fetchJob(parseInt(id))
      .then(setJob)
      .catch(err => toast.error('Failed to fetch job: ' + err))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <div className="p-8 text-center">Loading...</div>;
  if (!job) return <div className="p-8 text-center">Job not found</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Job #{job.id}: {job.name}</h1>
        <Link to="/jobs">
          <Button variant="outline">Back to Jobs</Button>
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Job Details</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <div>
              <dt className="text-sm font-medium text-gray-500">Status</dt>
              <dd>
                <span className={`px-2 py-1 rounded text-xs font-medium ${
                  job.status === 'completed' ? 'bg-green-100 text-green-800' :
                  job.status === 'running' ? 'bg-blue-100 text-blue-800' :
                  job.status === 'failed' ? 'bg-red-100 text-red-800' :
                  job.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {job.status}
                </span>
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Config ID</dt>
              <dd>{job.config_id || 'none'}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Target</dt>
              <dd className="font-mono text-sm">{job.target}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Created</dt>
              <dd>{new Date(job.created_at).toLocaleString()}</dd>
            </div>
            {job.started_at && (
              <div>
                <dt className="text-sm font-medium text-gray-500">Started</dt>
                <dd>{new Date(job.started_at).toLocaleString()}</dd>
              </div>
            )}
            {job.finished_at && (
              <div>
                <dt className="text-sm font-medium text-gray-500">Finished</dt>
                <dd>{new Date(job.finished_at).toLocaleString()}</dd>
              </div>
            )}
            {job.error && job.error.Valid && (
              <div className="col-span-2">
                <dt className="text-sm font-medium text-red-600">Error</dt>
                <dd className="text-red-600 bg-red-50 p-2 rounded">{job.error.String}</dd>
              </div>
            )}
          </dl>
        </CardContent>
      </Card>

      {job.results && job.results.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Scan Results</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {job.results.map((res, idx) => (
              <div key={idx} className="border rounded-lg overflow-hidden">
                <div className="bg-gray-50 px-4 py-2 border-b flex items-center justify-between">
                  <span className="font-medium">
                    {res.result_type.toUpperCase()} – {res.target || 'root'}
                  </span>
                  {res.class && (
                    <span className="text-sm text-gray-600">{res.class}</span>
                  )}
                </div>
                <div className="p-4 bg-gray-50 overflow-auto max-h-96">
                  <pre className="text-xs font-mono">
                    {JSON.stringify(res.data, null, 2)}
                  </pre>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Scan Results</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground">No results found for this job.</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}