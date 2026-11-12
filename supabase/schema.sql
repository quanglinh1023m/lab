CREATE TABLE IF NOT EXISTS public.pages (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  html_content TEXT NOT NULL,
  edit_pin TEXT NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Idempotent migration for existing tables
ALTER TABLE public.pages ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE public.pages ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

-- Block anonymous public access to PIN hashes via Supabase REST API
ALTER TABLE public.pages ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_pages_updated_at ON public.pages;
CREATE TRIGGER trg_pages_updated_at
  BEFORE UPDATE ON public.pages
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

