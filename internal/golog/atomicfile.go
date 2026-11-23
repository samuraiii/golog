package golog

import (
	"os"
	"path/filepath"
)

// writeFileAtomic replaces path with data: a fresh temporary file in the same
// directory (unpredictable name, created exclusively, never a symlink target),
// the mode of the old file kept when there is one, then a rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
