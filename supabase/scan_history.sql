create table if not exists public.scan_history (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  source_input text,
  target text not null,
  risk_score integer not null check (risk_score >= 0 and risk_score <= 100),
  confidence_score integer not null check (confidence_score >= 0 and confidence_score <= 100),
  risk_level text not null check (risk_level in ('LOW', 'MEDIUM', 'HIGH')),
  threat_categories jsonb not null default '[]'::jsonb,
  detection jsonb not null default '{}'::jsonb,
  geolocation jsonb not null default '{}'::jsonb,
  summary text not null
);

alter table public.scan_history add column if not exists source_input text;

create index if not exists scan_history_created_at_idx on public.scan_history (created_at desc);
create index if not exists scan_history_target_idx on public.scan_history (target);

alter table public.scan_history enable row level security;

-- Allow public insert/select for demo usage with anon key.
do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'scan_history' and policyname = 'scan_history_select_all'
  ) then
    create policy scan_history_select_all
      on public.scan_history
      for select
      to anon, authenticated
      using (true);
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'scan_history' and policyname = 'scan_history_insert_all'
  ) then
    create policy scan_history_insert_all
      on public.scan_history
      for insert
      to anon, authenticated
      with check (true);
  end if;
end $$;
