# Finding: Missing Supabase RLS

## Why it's dangerous
Supabase tables expose data direct-to-client via PostgREST endpoints. If Row Level Security (RLS) is disabled, anyone can read, edit, or delete any record in the database using simple client APIs without any validation check.

## How to fix it
Execute the SQL command to explicitly enable Row Level Security on the target table, and create granular security policies mapping user Auth IDs to record ownership properties.

## Before (vulnerable)
```sql
-- Profiles table is created but has RLS disabled (default is open to all anonymous requests)
CREATE TABLE profiles (
  id uuid REFERENCES auth.users,
  username text
);
```

## After (fixed)
```sql
-- Explicitly lock down the table and restrict SELECT scopes to account owners
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can only see own data"
ON profiles FOR SELECT
USING (auth.uid() = id);
```
