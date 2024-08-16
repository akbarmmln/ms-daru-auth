const errCode = {
  '10000': 'internal server error',
  '90001': 'data tidak ditemukan',
  '90002': 'data belum ter-register',
  '90003': 'pin not valid',
  '90004': 'data telah ter-register',
  '90005': 'register telah ditutup',
  '90006': 'missing parameter access token',
  '90007': 'missing parameter nomor kk',
  '90008': 'missing parameter pin',
  '90009': 'missing parameter device id',
  '90010': 'verify token failed or not match',
  '90011': 'akun ter-blokir',
  '90012': 'login blocked',
  '90013': 'token expired',
};

module.exports = errCode;