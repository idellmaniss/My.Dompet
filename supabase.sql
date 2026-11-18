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

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'transactions'
      and policyname = 'Users can view their own transactions'
  ) then
    execute $policy$
      create policy "Users can view their own transactions"
        on public.transactions for select
        using (auth.uid() = user_id)
    $policy$;
  end if;
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'transactions'
      and policyname = 'Users can insert their own transactions'
  ) then
    execute $policy$
      create policy "Users can insert their own transactions"
        on public.transactions for insert
        with check (auth.uid() = user_id)
    $policy$;
  end if;
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'transactions'
      and policyname = 'Users can update their own transactions'
  ) then
    execute $policy$
      create policy "Users can update their own transactions"
        on public.transactions for update
        using (auth.uid() = user_id)
        with check (auth.uid() = user_id)
    $policy$;
  end if;
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'transactions'
      and policyname = 'Users can delete their own transactions'
  ) then
    execute $policy$
      create policy "Users can delete their own transactions"
        on public.transactions for delete
        using (auth.uid() = user_id)
    $policy$;
  end if;
end
$$;

alter table public.transactions
  add column if not exists receipt_path text;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'transaction-receipts',
  'transaction-receipts',
  false,
  5242880,
  array['image/jpeg', 'image/png', 'image/webp']::text[]
)
on conflict (id) do nothing;

do $$
declare
  bucket_config record;
begin
  select public, file_size_limit, allowed_mime_types
    into bucket_config
    from storage.buckets
    where id = 'transaction-receipts';

  if not found
    or bucket_config.public is distinct from false
    or bucket_config.file_size_limit is distinct from 5242880
    or bucket_config.allowed_mime_types is null
    or not (
      bucket_config.allowed_mime_types <@ array['image/jpeg', 'image/png', 'image/webp']::text[]
      and array['image/jpeg', 'image/png', 'image/webp']::text[] <@ bucket_config.allowed_mime_types
    )
  then
    raise exception 'Bucket transaction-receipts sudah ada dengan konfigurasi berbeda. Periksa bucket tersebut secara manual; SQL tidak mengubah konfigurasi yang sudah ada.';
  end if;
end
$$;

do $$
begin
  if exists (
    select 1
      from pg_policies
      where schemaname = 'storage'
        and tablename = 'objects'
        and policyname not in (
          'transaction_receipts_select_own',
          'transaction_receipts_insert_own',
          'transaction_receipts_delete_own'
        )
        and (
          coalesce(qual, '') like '%transaction-receipts%'
          or coalesce(with_check, '') like '%transaction-receipts%'
        )
  ) then
    raise exception 'Kebijakan Storage untuk transaction-receipts sudah ada dengan nama lain. Tinjau kebijakan tersebut sebelum melanjutkan agar aturan akses tidak bertumpuk.';
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and policyname = 'transaction_receipts_select_own'
  ) then
    execute $policy$
      create policy transaction_receipts_select_own
        on storage.objects for select to authenticated
        using (
          bucket_id = 'transaction-receipts'
          and (storage.foldername(name))[1] = auth.uid()::text
          and exists (
            select 1 from public.transactions as transaction_row
            where transaction_row.id::text = (storage.foldername(name))[2]
              and transaction_row.user_id = auth.uid()
          )
        )
    $policy$;
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and policyname = 'transaction_receipts_insert_own'
  ) then
    execute $policy$
      create policy transaction_receipts_insert_own
        on storage.objects for insert to authenticated
        with check (
          bucket_id = 'transaction-receipts'
          and (storage.foldername(name))[1] = auth.uid()::text
          and exists (
            select 1 from public.transactions as transaction_row
            where transaction_row.id::text = (storage.foldername(name))[2]
              and transaction_row.user_id = auth.uid()
          )
        )
    $policy$;
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and policyname = 'transaction_receipts_delete_own'
  ) then
    execute $policy$
      create policy transaction_receipts_delete_own
        on storage.objects for delete to authenticated
        using (
          bucket_id = 'transaction-receipts'
          and (storage.foldername(name))[1] = auth.uid()::text
        )
    $policy$;
  end if;
end
$$;
