/// Wraps a [`Vec`] to allow stateful iterating.
///
/// We need to use this instead of [`Iterator`] because we need to own the
/// [`Vec`], whereas `Vec::iter` returns an iterator over a _slice_ of the
/// [`Vec`]. We also need the ability to reset the iterator and set it to a
/// particular index.
pub(crate) struct VecWrapper<T> {
    vec: Vec<T>,
    index: usize,
}

impl<T: Copy> VecWrapper<T> {
    pub(crate) fn new(vec: Vec<T>) -> Self {
        Self { vec, index: 0 }
    }

    pub(crate) fn next(&mut self) -> T {
        let value = self.vec[self.index];
        self.index += 1;
        value
    }

    pub(crate) fn len(&self) -> usize {
        self.vec.len()
    }

    pub(crate) fn reset(&mut self) {
        self.index = 0;
    }

    pub(crate) fn set_index(&mut self, index: usize) {
        self.index = index
    }
}
