-- Fix Supabase Security Vulnerabilities for the Photography App
-- 1. Enable Row Level Security (RLS)
ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.photos ENABLE ROW LEVEL SECURITY;

-- 2. Drop any existing public permissive policies if they exist (ignoring errors if they don't)
DROP POLICY IF EXISTS "Enable public access" ON public.events;
DROP POLICY IF EXISTS "Enable public access" ON public.photos;

-- 3. RLS Policies for the `events` table
-- We only allow anonymous inserts. No SELECT, UPDATE, or DELETE policies.
CREATE POLICY "Allow anonymous inserts to events"
ON public.events 
FOR INSERT TO public 
WITH CHECK (true);

-- 4. RLS Policies for the `photos` table
-- We allow anonymous photo inserts only if the specific event token exists.
CREATE POLICY "Allow anonymous inserts to photos"
ON public.photos
FOR INSERT TO public
WITH CHECK (EXISTS (SELECT 1 FROM public.events WHERE token = photos.token));

-- 5. Secure fetching via Remote Procedure Calls (RPC functions)
-- These run as SECURITY DEFINER (admin) to securely fetch data bypassing the RLS select restrictions,
-- but the functions enforce exact token matching themselves.

-- Function to get an event by token
CREATE OR REPLACE FUNCTION public.get_event_by_token(p_token text)
RETURNS TABLE (name text)
LANGUAGE plpgsql
SECURITY DEFINER 
SET search_path = public
AS $$
BEGIN
  RETURN QUERY SELECT e.name FROM public.events e WHERE e.token = p_token;
END;
$$;

-- Function to get photos by token
CREATE OR REPLACE FUNCTION public.get_photos_by_token(p_token text)
RETURNS TABLE (id bigint, token text, url text, storage_path text, created_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER 
SET search_path = public
AS $$
BEGIN
  RETURN QUERY SELECT p.id, p.token, p.url, p.storage_path, p.created_at 
               FROM public.photos p 
               WHERE p.token = p_token 
               ORDER BY p.created_at DESC;
END;
$$;
