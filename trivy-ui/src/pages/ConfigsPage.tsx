import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ConfigForm } from '@/components/ConfigForm';
import { Config, fetchConfigs, deleteConfig, runConfig } from '@/lib/api';
import { toast } from 'sonner';

export function ConfigsPage() {
  const [configs, setConfigs] = useState<Config[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);

  const loadConfigs = async () => {
    try {
      const data = await fetchConfigs();
      setConfigs(data);
    } catch (err) {
      toast.error('Failed to fetch configs: ' + err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadConfigs();
  }, []);

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure?')) return;
    try {
      await deleteConfig(id);
      await loadConfigs();
      toast.success('Configuration deleted');
    } catch (err) {
      toast.error('Failed to delete config: ' + err);
    }
  };

  const handleRun = async (id: number) => {
    try {
      const { job_id } = await runConfig(id);
      toast.success('Job created', { description: `Job ID: ${job_id}` });
    } catch (err) {
      toast.error('Failed to run config: ' + err);
    }
  };

  if (loading) return <div className="p-8 text-center">Loading...</div>;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Scan Configurations</CardTitle>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button>New Configuration</Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[600px]">
            <DialogHeader>
              <DialogTitle>Create Configuration</DialogTitle>
            </DialogHeader>
            <ConfigForm onSuccess={() => { setDialogOpen(false); loadConfigs(); }} />
          </DialogContent>
        </Dialog>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Target Pattern</TableHead>
              <TableHead>Scanners</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {configs.map(cfg => (
              <TableRow key={cfg.id}>
                <TableCell>{cfg.id}</TableCell>
                <TableCell>{cfg.name}</TableCell>
                <TableCell className="font-mono text-sm">{cfg.target_pattern}</TableCell>
                <TableCell>{cfg.scanners.join(', ')}</TableCell>
                <TableCell>{cfg.severity.join(', ')}</TableCell>
                <TableCell className="space-x-2">
                  <Button size="sm" variant="outline" onClick={() => handleRun(cfg.id)}>Run</Button>
                  <Button size="sm" variant="destructive" onClick={() => handleDelete(cfg.id)}>Delete</Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
