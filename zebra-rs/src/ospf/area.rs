use std::collections::BTreeMap;

pub struct OspfAreaMap {
    pub mapping: BTreeMap<u32, usize>,
    pub vec: Vec<Option<OspfArea>>,
}

pub trait MapVec {
    fn id(&self) -> usize;
    fn set_id(&mut self, id: usize);
}

impl OspfAreaMap {
    pub fn new() -> Self {
        Self {
            mapping: BTreeMap::new(),
            vec: Vec::new(),
        }
    }

    pub fn get(&self, area_id: u32) -> Option<&OspfArea> {
        let index = *self.mapping.get(&area_id)?;
        self.vec.get(index)?.as_ref()
    }

    pub fn get_mut(&mut self, area_id: u32) -> Option<&mut OspfArea> {
        let index = *self.mapping.get(&area_id)?;
        self.vec.get_mut(index)?.as_mut()
    }

    pub fn fetch(&mut self, area_id: u32) -> Option<&mut OspfArea> {
        let index = if let Some(&index) = self.mapping.get(&area_id) {
            index
        } else {
            let index = self.vec.len();
            self.mapping.insert(area_id, index);
            self.vec.push(None);
            index
        };
        if self.vec[index].is_none() {
            self.vec[index] = Some(OspfArea::new(index, area_id));
        }
        self.vec.get_mut(index).and_then(|slot| slot.as_mut())
    }
}

pub struct OspfArea {
    pub id: usize,
    pub area_id: u32,
}

impl OspfArea {
    pub fn new(id: usize, area_id: u32) -> Self {
        Self { id, area_id }
    }
}

impl MapVec for OspfArea {
    fn id(&self) -> usize {
        self.id
    }

    fn set_id(&mut self, id: usize) {
        self.id = id;
    }
}
