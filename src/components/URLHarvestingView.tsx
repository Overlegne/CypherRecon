"use client";

import { useState } from 'react';
import { URLHarvestingData, HarvestedURL } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Input } from './ui/input';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Search, Link as LinkIcon, ExternalLink, Filter, Star } from 'lucide-react';
import { cn } from '@/lib/utils';

export function URLHarvestingView({ data }: { data: URLHarvestingData }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string | 'all'>('all');

  const filteredUrls = data.urls.filter(u => {
    const matchesSearch = u.url.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === 'all' || u.type === filterType;
    return matchesSearch && matchesType;
  });

  const getTypeBadge = (type: HarvestedURL['type']) => {
    switch (type) {
      case 'api': return <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">API</Badge>;
      case 'admin': return <Badge className="bg-red-500/20 text-red-400 border-red-500/30">ADMIN</Badge>;
      case 'static': return <Badge variant="secondary" className="text-[10px]">Static</Badge>;
      default: return <Badge variant="outline" className="text-[10px]">Page</Badge>;
    }
  };

  const getSourceBadge = (source: HarvestedURL['source']) => {
    return <span className="text-[10px] text-muted-foreground uppercase tracking-widest">{source}</span>;
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-secondary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code">{data.summary.found}</span>
            <span className="text-xs text-muted-foreground uppercase">URLs Found</span>
          </CardContent>
        </Card>
        <Card className="bg-secondary/20 border-blue-500/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-blue-400">{data.summary.api_endpoints}</span>
            <span className="text-xs text-muted-foreground uppercase">API Endpoints</span>
          </CardContent>
        </Card>
        <Card className="bg-secondary/20 border-yellow-500/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-yellow-400">{data.summary.interesting}</span>
            <span className="text-xs text-muted-foreground uppercase">High Priority</span>
          </CardContent>
        </Card>
        <Card className="bg-secondary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code">{data.summary.unique}</span>
            <span className="text-xs text-muted-foreground uppercase">Unique Paths</span>
          </CardContent>
        </Card>
      </div>

      <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="relative w-full md:w-96">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={16} />
          <Input 
            placeholder="Search URLs..." 
            className="pl-10"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="flex gap-2">
          {['all', 'api', 'admin', 'page', 'static'].map((t) => (
            <Button
              key={t}
              variant={filterType === t ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFilterType(t)}
              className="capitalize"
            >
              {t}
            </Button>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader className="pb-3 border-b border-border/40">
          <CardTitle className="text-lg flex items-center gap-2">
            <LinkIcon size={18} className="text-primary" />
            Discovered Endpoint Map
          </CardTitle>
          <CardDescription>
            Normalized list of reachable resources and internal paths.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="max-h-[600px] overflow-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-background z-10">
                <TableRow>
                  <TableHead className="w-10"></TableHead>
                  <TableHead>Endpoint URL</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredUrls.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-20 text-center text-muted-foreground italic">
                      No URLs match your current filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredUrls.map((u, idx) => (
                    <TableRow key={idx} className={cn("group hover:bg-muted/30", u.interesting && "bg-yellow-500/5")}>
                      <TableCell>
                        {u.interesting && <Star size={14} className="text-yellow-500 fill-yellow-500" />}
                      </TableCell>
                      <TableCell className="max-w-[400px]">
                        <div className="font-code text-xs truncate" title={u.url}>
                          {u.url}
                        </div>
                      </TableCell>
                      <TableCell>{getTypeBadge(u.type)}</TableCell>
                      <TableCell>{getSourceBadge(u.source)}</TableCell>
                      <TableCell className="text-right">
                        <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => window.open(u.url, '_blank')}>
                          <ExternalLink size={14} />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
