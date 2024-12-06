#[derive(Clone, Debug, PartialEq, Eq)] pub enum Form{}
#[derive(Clone, Debug, PartialEq, Eq)] pub struct Scalar
{
    name:       String,
    bitness:    u16,
    form:       Option<Form>,
}

impl Scalar
{
    pub fn new(name: impl ToString, bitness: u16)
        -> Self
    {
        Self
        {
            name: name.to_string(),
            bitness,
            form: None
        }
    }

    pub fn set_form(&mut self, form: Option<Form>)
    {
        self.form = form
    }

    pub fn get_form(&self)
        -> Option<&Form>
    {
        self.form.as_ref()
    }

    pub fn get_str(&self)
        -> &str
    {
        self.name.as_str()
    }

    pub fn bitness(&self)
        -> &u16
    {
        &self.bitness
    }
}
