use sha2::Digest;
use kzg::opening::KzgOpening;
use kzg::scheme::KzgScheme;
use kzg::types::ScalarField;
use crate::nifs::{FInstance, FWitness, NIFS, NIFSProof};
use crate::transcript::Transcript;


impl <T: Digest + Default> NIFS<T> {
    pub fn prove(
        r: ScalarField,
        fw: &FWitness,
        fi: &FInstance,
        scheme: &KzgScheme,
        transcript: &mut Transcript<T>,
    ) -> NIFSProof {

        // opening = Transcript(fi_cmE, fi_cmW);
        transcript.feed(&fi.com_e);
        transcript.feed(&fi.com_w);
        let [opening_point] = transcript.generate_challenges();

        let opening_e = scheme.open_vector(&fw.e, opening_point);
        let opening_w = scheme.open_vector(&fw.w, opening_point);

        NIFSProof {
            r,
            opening_point,
            opening_e: opening_e,
            opening_w: opening_w
        }
    }
}