// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

type Paginator struct {
	Limit int    // Number of results to return.
	Page  int    // Start page
	Sort  string // Sort order requested for results.
}

func (p *Paginator) GetOffset() int {
	return (p.GetPage() - 1) * p.GetLimit()
}

func (p *Paginator) GetLimit() int {
	switch {
	case p.Limit > maxDbQueryPageSize:
		p.Limit = maxDbQueryPageSize
	case p.Limit <= 0:
		p.Limit = 10
	}
	return p.Limit
}

func (p *Paginator) GetPage() int {
	if p.Page == 0 {
		p.Page = 1
	}
	return p.Page
}

func (p *Paginator) GetSort() string {
	if p.Sort == "" {
		p.Sort = "created_at asc"
	}
	return p.Sort
}
