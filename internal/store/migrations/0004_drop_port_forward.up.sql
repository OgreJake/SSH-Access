-- ADR-014 (revised): port-forwarding is descoped. Drop the per-grant flag.
-- The low-level cert capability (ca.Permissions.PortForwarding) and the
-- channel_type enum value remain, but policy no longer offers port-forwarding.
ALTER TABLE grants DROP COLUMN IF EXISTS allow_port_forward;
