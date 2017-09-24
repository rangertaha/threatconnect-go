package threatconnect

type Paginator interface {
	Page() *Resourcer
	Next() *Resourcer
	Previous() *Resourcer
}

type paginator struct {
	resource *Resourcer
}

func NewPaginator(resource *Resourcer) *paginator {
	return &paginator{resource: resource}
}

func (p *paginator) Page() *Resourcer {
	return nil
}

func (p *paginator) Next() *Resourcer {
	return nil
}

func (p *paginator) Previous() *Resourcer {
	return nil
}
