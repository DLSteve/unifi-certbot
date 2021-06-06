package errors

type DataStoreErr struct {
	NotFound bool
	Err      error
}

func (d *DataStoreErr) IsNotFound() bool {
	return d.NotFound
}

func (d *DataStoreErr) Error() string {
	return d.Err.Error()
}
