pub struct TranscriptLabel;

/// The labels used in transcript generator
impl TranscriptLabel {
    pub const NAME: &'static [u8] = b"lookup";
    pub const ZETA: &'static [u8] = b"zeta";
    pub const T_COMMIT: &'static [u8] = b"t_commit";
    pub const T_I_COMMIT: &'static [u8] = b"t_i_commit";
    pub const F_COMMIT: &'static [u8] = b"f_commit";
    pub const F_I_COMMIT: &'static [u8] = b"f_i_commit";
    pub const H1_COMMIT: &'static [u8] = b"h1_commit";
    pub const H2_COMMIT: &'static [u8] = b"h2_commit";
    pub const BETA: &'static [u8] = b"beta";
    pub const GAMMA: &'static [u8] = b"gamma";
    pub const Z_COMMIT: &'static [u8] = b"z_commit";
    pub const Q_COMMIT: &'static [u8] = b"q_commit";
    pub const OPENING: &'static [u8] = b"opening";
    pub const F_EVAL: &'static [u8] = b"f_eval";
    pub const T_EVAL: &'static [u8] = b"t_eval";
    pub const H1_EVAL: &'static [u8] = b"h1_eval";
    pub const H2_EVAL: &'static [u8] = b"h2_eval";
    pub const Z_EVAL: &'static [u8] = b"z_eval";
    pub const Q_EVAL: &'static [u8] = b"q_eval";
    pub const T_G_EVAL: &'static [u8] = b"t_g_eval";
    pub const H1_G_EVAL: &'static [u8] = b"h1_g_eval";
    pub const H2_G_EVAL: &'static [u8] = b"h2_g_eval";
    pub const Z_G_EVAL: &'static [u8] = b"z_g_eval";
    pub const WITNESS_AGGREGATION: &'static [u8] = b"witness_aggregation";
}
