import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { toast } from 'sonner';
import { Scan, AlertCircle, Rocket } from 'lucide-react';

const API_BASE = 'http://localhost:8080/api/v1';

export function QuickScanPage() {
  const navigate = useNavigate();
  const [image, setImage] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!image.trim()) {
      setError('Please enter an image name');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/quick-scan`, { // ← исправлено
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target: image.trim(), // ← убрали type
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Failed to create scan');
      }

      const data = await response.json();
      toast.success('Scan created successfully', {
        description: `Job ID: ${data.id}`, // ← изменили текст на Job ID
      });
      
      navigate(`/jobs/${data.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      toast.error('Failed to create scan', {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Rocket className="h-5 w-5" />
            Quick Scan
          </CardTitle>
          <CardDescription>
            Quickly scan a container image without creating a configuration
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="image">Container Image</Label>
              <Input
                id="image"
                placeholder="e.g., alpine:3.18, vulnerables/cve-2014-6271:latest"
                value={image}
                onChange={(e) => setImage(e.target.value)}
                disabled={loading}
              />
              <p className="text-sm text-muted-foreground">
                Enter the full image name including tag
              </p>
            </div>

            {error && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button type="submit" disabled={loading} className="w-full">
              {loading ? (
                <>
                  <Scan className="mr-2 h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Scan className="mr-2 h-4 w-4" />
                  Start Scan
                </>
              )}
            </Button>
          </form>

          <div className="mt-6 pt-6 border-t">
            <h3 className="text-sm font-medium mb-2">Examples:</h3>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setImage('alpine:3.18')}
              >
                alpine:3.18
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setImage('vulnerables/cve-2014-6271:latest')}
              >
                vulnerables/cve-2014-6271
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setImage('nginx:latest')}
              >
                nginx:latest
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}