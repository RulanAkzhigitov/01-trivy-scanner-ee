import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { createConfig } from '@/lib/api';
import { toast } from 'sonner';

// Схема без .default() — все поля обязательные
const formSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  description: z.string().optional(),
  target_type: z.enum(['image', 'filesystem']),
  target_pattern: z.string().min(1, 'Target pattern is required'),
  scanners: z.array(z.string()),
  severity: z.array(z.string()),
  ignore_unfixed: z.boolean(),
  detection_priority: z.enum(['precise', 'comprehensive']),
});

type FormValues = z.infer<typeof formSchema>;

interface Props {
  onSuccess: () => void;
}

export function ConfigForm({ onSuccess }: Props) {
  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: '',
      description: '',
      target_type: 'image',
      target_pattern: '',
      scanners: ['vuln', 'secret'],
      severity: ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      ignore_unfixed: false,
      detection_priority: 'precise',
    },
  });

  const onSubmit = async (data: FormValues) => {
    try {
      await createConfig(data);
      toast.success('Configuration created successfully');
      onSuccess();
    } catch (err) {
      toast.error('Failed to create config: ' + err);
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Name</FormLabel>
              <FormControl>
                <Input {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description</FormLabel>
              <FormControl>
                <Input {...field} value={field.value || ''} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="target_pattern"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Target Pattern</FormLabel>
              <FormControl>
                <Input {...field} placeholder="harbor.example.com/library/*" />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="detection_priority"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Detection Priority</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select priority" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="precise">Precise (fewer false positives)</SelectItem>
                  <SelectItem value="comprehensive">Comprehensive (more findings)</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="ignore_unfixed"
          render={({ field }) => (
            <FormItem className="flex flex-row items-start space-x-3 space-y-0">
              <FormControl>
                <Checkbox checked={field.value} onCheckedChange={field.onChange} />
              </FormControl>
              <div className="space-y-1 leading-none">
                <FormLabel>Ignore unfixed vulnerabilities</FormLabel>
              </div>
            </FormItem>
          )}
        />
        <Button type="submit">Create Configuration</Button>
      </form>
    </Form>
  );
}