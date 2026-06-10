package store

import (
	"context"
	"fmt"
)

// GroupRow is a group with its member count, for listings.
type GroupRow struct {
	ID      string
	Name    string
	Members int
}

func (s *Store) ListUserGroups(ctx context.Context) ([]GroupRow, error) {
	return s.listGroups(ctx,
		`SELECT g.id::text, g.name,
		        (SELECT count(*) FROM user_group_members m WHERE m.user_group_id = g.id)
		 FROM user_groups g ORDER BY g.name`)
}

func (s *Store) ListServerGroups(ctx context.Context) ([]GroupRow, error) {
	return s.listGroups(ctx,
		`SELECT g.id::text, g.name,
		        (SELECT count(*) FROM server_group_members m WHERE m.server_group_id = g.id)
		 FROM server_groups g ORDER BY g.name`)
}

func (s *Store) listGroups(ctx context.Context, q string) ([]GroupRow, error) {
	rows, err := s.Pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()
	var out []GroupRow
	for rows.Next() {
		var g GroupRow
		if err := rows.Scan(&g.ID, &g.Name, &g.Members); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
