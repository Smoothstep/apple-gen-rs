use pyo3::{pymodule, Python, types::PyModule, PyResult, pyclass, pymethods, PyRef};

extern crate pyo3;

#[pyclass]
struct IDS {
    validator: apple_auth_utils::IDSValidator
}

#[pymethods]
impl IDS {
    #[new]
    fn new(js: &str, cert: Option<Vec<u8>>) -> PyResult<Self> {
        match apple_auth_utils::IDSValidator::from_json(js, cert) {
            Err(err) => Err(pyo3::exceptions::PyRuntimeError::new_err(std::format!("{}", err))),
            Ok(validator) => Ok(Self {
                validator
            })
        }
    }

    fn request_validation_data(self_: PyRef<'_, Self>) -> PyResult<Vec<u8>> {
        let validator = &self_.validator;

        self_.py().allow_threads(move || -> PyResult<Vec<u8>> {
            match validator.request_validation_data() {
                Err(err) => Err(pyo3::exceptions::PyRuntimeError::new_err(std::format!("{}", err))),
                Ok(data) => Ok(data)
        }})
    }

    fn encrypt_io_data(self_: PyRef<'_, Self>, data: &[u8]) -> PyResult<Vec<u8>> {
        self_.py().allow_threads(move || -> PyResult<Vec<u8>> {
            match apple_auth_utils::IDSValidator::encrypt_value(data) {
                Err(err) => Err(pyo3::exceptions::PyRuntimeError::new_err(std::format!("{}", err))),
                Ok(data) => Ok(data)
        }})
    }
}

#[pymodule]
fn apple_auth(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<IDS>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use pyo3::{types::PyModule, PyCell, py_run};

    #[test]
    fn test_ids() {
        pyo3::prepare_freethreaded_python();

        pyo3::marker::Python::with_gil(|py|  {
            let module = PyModule::new(py, "apple_auth").unwrap();
            crate::apple_auth(py, &module).unwrap();

            let sample_data = r#"{
                "rom": "0C66833E0010",
                "board_id": "Mac-27AD2F918AE68F65",
                "product_name": "MacPro7,1",
                "mac": "5C:F7:FF:00:00:0F",
                "platform_serial": "F5KGCVYKP7QM",
                "mlb": "F5K925600QXFHDD1M",
                "root_disk_uuid": "6015372F-2EA0-4634-B85D-AEFB9E03DF00",
                "platform_uuid": "564D3AEF-EAF0-868D-B8B2-623A10E88A26"
            }"#;

            let ids = crate::IDS::new(sample_data, None).expect("Failed to construct ids");            
            let ids = PyCell::new(py, ids).expect("Failed to create PyCell from IDS");

            py_run!(py, ids, r#"assert len(ids.request_validation_data()) >= 389"#);
        });
    }
}