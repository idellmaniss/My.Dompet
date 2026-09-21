create table if not exists public.transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  type text not null check (type in ('income', 'expense')),
  amount numeric not null check (amount > 0),
  category text not null,
  date date not null,
  note text,
  created_at timestamp with time zone not null default now()
);

alter table public.transactions enable row level security;

create policy "Users can view their own transactions"
  on public.transactions for select
  using (auth.uid() = user_id);

create policy "Users can insert their own transactions"
  on public.transactions for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own transactions"
  on public.transactions for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own transactions"
  on public.transactions for delete
  using (auth.uid() = user_id);
