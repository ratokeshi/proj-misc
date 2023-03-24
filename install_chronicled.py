#!/usr/bin/python2.7
# NOTE: The shebang line is to maintain backward compatiblity for existing
# users.  The script works with python3 if you call it that way:
#   python3 install_chronicled.py

import sys

MIN_PYTHON = (2, 7)
if sys.version_info < MIN_PYTHON:
  sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

if sys.version_info[0] == 2:
  requests_rpm = "python-requests"
else:
  requests_rpm = "python3-requests"

import subprocess

try:
  import requests
except ImportError:
  subprocess.call(["yum", "-y", "install", requests_rpm])
  try:
    import requests
  except ImportError:
    sys.exit("requests python module not found")

import argparse, datetime, errno, hashlib, hmac, json, os, syslog, time

# The default Chronicle version.
# Should be updated with each new Chronicle release
DEFAULT_CHRONICLE_VERSION = "chronicled-2.0.1575.0-1_naws"

# The aws-sec-informatics RPM signing key.
PUBLIC_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQINBFzKMpgBEACrasdQqYhqFEV5dNE34FpkY6xZ1RXiplb//aVIGZagkuuhRchU
AwQwWAoVqj4+YUYdObBQmGgu9if1kMTmo4vA7lyjaol/fRNQW7abDbvLUeHObzrz
c5aPvYz5yy4kXM6pTvmFHWDx74+AhUNkklRFDxhpAX5wIBzGnMtQFu0tKezFdwXj
OSCBooDNVKqRXXwi+qwRedhLevGHOLeB3PmUPl4nukEf26IH18UN4WGl5s1SAlei
bD+OkA6Xp5M5FWgmeFcD9YjM7J2tVD80P/4TMwQa9AfYX8yX0jHWSdIyVMcwGsRY
fXMWvt3VkOLFKCOugWCFr6xj+ogHfTXFo0YN9kKKTdBkqgtcdC0HgIEOzdJVsVuO
tQKNjSalzs7tceyqAMW0+zu80TXKXLk6HL41TUY5nptfyWn9sKaWTY74qYAT1WGy
h1Byn+DBFD4BI9uO3CLreDF9oYCcVzPJzAQ4OulvpOuMX3U+J5nMRO0DZeoavFbb
4WpjeobkXB9L2V8tkqNTY1Vn4S/MinpRmUmsQJFjCAG/ZcTejiCJI9mc1/mCcihX
LGOudztnnYkLBbK9Nmux+tE0LRThIcM8F6JnC7Y42fjEn4xnpjpi+C5p5lA80xF2
JVkr+xquoprKasp+/mYEPQX9NwbXzkRKY6S4tJ1bX9H7G6WI7Ynvp6MCJwARAQAB
tDRhd3Mtc2VjLWluZm9ybWF0aWNzIDxhd3Mtc2VjLWluZm9ybWF0aWNzQGFtYXpv
bi5jb20+iQI5BBMBCAAjBQJcyjKYAhsDBwsJCAcDAgEGFQgCCQoLBBYCAwECHgEC
F4AACgkQxsHtsCiC8moNyA/+OadXPTpDE55B9sCQmd0HBRnAN++GJMmxYclLc6Yv
Y9G7sG0b3TaT7KMgr6Mfn73LF59Aq8KfGvydQYuEfp/ig68+G3Bf4/XluPwrywMg
dlWefHfd1pcOkIAQA5hhE1ApviAGDrvJYFGx7o1lj4Aw0QPBFNcVCmWsbV8zY3pa
MuYm+sAA/TQsjtO9RhUi/aShTEBfUVv0pFNMJc5aYNhHnpiJUHpEKgfcYJIjMXsi
zpkngeZoHvULDoPP8CPlHmPvR9zrj5EH1UnBsmvigcK9Dlcl3xv5NwnL7Gv7xMVc
d0Y97nWAqRMpSJW2aJWE5yGSEYivi/VQXFCUdd7I0FNZJg98w2iP69HYV+WKdbxJ
+T45yHGPtFyEYiEuiUt7idJzfE2zx0Wv0j3tVBXsS2w2gKvsRQoP/tdiiqbaTkCz
LJO7szQAu1PrrBzACqNp78EdWUgnFamLD+Fr++VHXemPiDDCisLWuXV/4oS+MMCL
kL1ylOZWbZ+DZ4yBgUMgValIAjfNQ3LZ/XmRY7iOsoPULhHExlkuKk5PzRvNcWnR
mMM/Qm+lzQt+SbU/I2uy9tSLvPHZYlHTy/3OMk7wBVKL2GSY4fUU1f4GiePs6fZT
WZ8WYQO4gb7PBNqz4SDOETE5ntvXrUrg5AaNLBxCtn7K5ExD03bbk2n2HUVRI3YB
z5s=
=+Q8r
-----END PGP PUBLIC KEY BLOCK-----
"""

CHRONICLE_DIR = "/usr/local/chronicle"
RPM_PATH = "/usr/local/chronicle/chronicled.rpm"
KEY_PATH = "/usr/local/chronicle/public_key"

error_exit_code = 0

def log(msg):
  print(msg)
  # 80 is LOG_AUTHPRIV
  syslog.syslog(80 | syslog.LOG_ERR, msg)


def log_exit(msg):
  log(msg)
  sys.exit(error_exit_code)


def decode_output(error):
  # In python 3, the subprocess output is in bytes but is a
  # string in python 2 so we try to convert.
  output = error.output
  try:
    output = output.decode()
  except (UnicodeDecodeError, AttributeError):
    pass
  return output


def get_metadata(uri, token):
  headers = {"X-aws-ec2-metadata-token": token}
  response = attempt_request(5, "get", "http://169.254.169.254" + uri, headers=headers, timeout=5)
  if response.status_code != requests.codes.ok:
    log_exit("bad response when querying IMDS: %s" % response.status_code)

  data = response.content
  try:
    data = data.decode()
  except (UnicodeDecodeError, AttributeError):
    pass
  return data

def get_region_and_creds():
  response = attempt_request(
    5, "put", "http://169.254.169.254/latest/api/token", 
    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, timeout=5
  )
  if response.status_code != requests.codes.ok:
    log_exit("bad response when getting token from IMDS: %s" % response.status_code)
  token = response.content
  response = get_metadata("/latest/dynamic/instance-identity/document", token)
  region = json.loads(response)["region"]
  cred_uri = "/latest/meta-data/iam/security-credentials/"
  role_name = get_metadata(cred_uri, token)
  response = get_metadata(cred_uri+role_name, token)
  creds = json.loads(response)
  return region, creds["AccessKeyId"], creds["SecretAccessKey"], creds["Token"]


def is_audit_installed():
  try:
    subprocess.check_output(["rpm", "-q", "audit"], stderr=subprocess.STDOUT)
    return True
  except subprocess.CalledProcessError:
    return False


def remove_audit():
  # Removing the audit package doesn't always stop the daemon, so do that first.
  subprocess.call(["/sbin/service", "auditd", "stop"])

  try:
    subprocess.check_output(
      ["yum", "-y", "remove", "audit"], stderr=subprocess.STDOUT
    )
  except subprocess.CalledProcessError as e:
    output = decode_output(e)
    log("Unable to remove audit: %s" % output)


def make_dir():
  try:
    os.makedirs(CHRONICLE_DIR, 0o700)
  except OSError as e:
    if e.errno != errno.EEXIST:
      log_exit(str(e))

    # If the directory already exists, just make sure it's got the right mode.
    os.chmod(CHRONICLE_DIR, 0o700)


def sign(key, msg):
  return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sign_request(host, uri, region, service, access_key, secret_key, session_token):
  t = datetime.datetime.utcnow()
  amz_date = t.strftime('%Y%m%dT%H%M%SZ')
  date_stamp = t.strftime('%Y%m%d')

  ch = "host:%s\nx-amz-date:%s\n" % (host, amz_date)
  sh = "host;x-amz-date"
  if session_token:
    ch = ch + "x-amz-security-token:%s\n" % session_token
    sh = sh + ";x-amz-security-token"

  cr = "GET\n%s\n\n%s\n%s\n%s" % (uri, ch, sh, hashlib.sha256("".encode("utf-8")).hexdigest())
  cr_hash = hashlib.sha256(cr.encode("utf-8")).hexdigest()

  msg = "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s" % \
    (amz_date, date_stamp, region, service, cr_hash)

  k = ("AWS4"+secret_key).encode("utf-8")
  skey = sign(sign(sign(sign(k, date_stamp), region), service), "aws4_request")
  sig = hmac.new(skey, msg.encode("utf-8"), hashlib.sha256).hexdigest()
  cred = '/'.join((access_key, date_stamp, region, service, "aws4_request"))
  authz = "AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s" % (cred, sh, sig)

  headers = {"X-Amz-Date": amz_date, "Authorization": authz}
  if session_token != "":
    headers["X-Amz-Security-Token"] = session_token
  return headers


def attempt_request(retry_count, method, url, **args):
  attempts = 0
  backoff_factor = 0.2
  while attempts < retry_count:
    attempts += 1
    try:
      results = requests.request(method, url, **args)
      if results.status_code != requests.codes.ok:
        if results.status_code in [500, 503]:
          time.sleep(4)
          raise Exception(
            "potential throttling, got response code: %s"
            % results.status_code
          )
        elif results.status_code > 400:
          raise Exception("unexpected response code: %s" % results.status_code)
      return results
    except Exception as e:
      # Here we want to wait to give the network time to recover
      log(str(e))
      time.sleep(backoff_factor * (2 ** (attempts - 1)))
  # On our last attempt, we want to just pass the request back up the call stack
  return requests.request(method, url, **args)


def install_rpm():
  # In order to support pipeline rollbacks, try to downgrade if install
  # comes back with nothing to do.
  for method in ("install", "downgrade"):
    try:
      subprocess.check_output(["yum", "-y", method, RPM_PATH], stderr=subprocess.STDOUT)
      return
    except subprocess.CalledProcessError as e:
      output = decode_output(e)
      if "Nothing to do" not in output:
        log_exit("Unable to install chronicle: %s" % output)


def download_rpm(ver):
  # Call the API to get a presigned URL, and download it.
  region, access_key, signing_key, session_token = get_region_and_creds()

  if region == "us-iso-east-1":
    host = "chronicle-control-prod.%s.c2s.ic.gov" % region
  elif region == "us-iso-west-1":
    host = "control.prod.%s.chronicle.security.c2s-a2z.ic.gov" % region
  elif region == "us-isob-east-1":
    host = "chronicle-control-prod.%s.sc2s.sgov.gov" % region
  elif region == "cn-north-1" or region == "cn-northwest-1":
    host = "control.prod.%s.chronicle.security.aws.a2z.org.cn" % region
  else:
    host = "control.prod.%s.chronicle.security.aws.a2z.com" % region
  uri = "/rpm/%s" % ver
  url = "https://%s%s" % (host, uri)

  headers = sign_request(host, uri, region, "aws-chronicle-collection", access_key, signing_key, session_token)

  mvp_ca_bundle = "/etc/pki/%s/certs/ca-bundle.pem" % region
  if region.startswith("us-iso"):
    response = attempt_request(5, "get", url, headers=headers, verify=mvp_ca_bundle, timeout=10)
  else:
    response = attempt_request(5, "get", url, headers=headers, timeout=10)

  if response.status_code != requests.codes.ok:
    log_exit("bad response when getting RPM url: %s" % response.status_code)
  presigned_url = response.content

  if region.startswith("us-iso"):
    response = attempt_request(5, "get", presigned_url, verify=mvp_ca_bundle, timeout=10)
  else:
    response = attempt_request(5, "get", presigned_url, timeout=10)

  if response.status_code != requests.codes.ok:
    log_exit("bad response when getting RPM contents: %s" % response.status_code)
  data = response.content

  with open(RPM_PATH, "wb") as outf:
    outf.write(data)


def verify_rpm():
  # Install the public key.
  with open(KEY_PATH, "wb") as outf:
    outf.write(PUBLIC_KEY.encode("utf-8"))
  try:
    subprocess.check_output(["rpm", "--import", KEY_PATH], stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError as e:
    output = decode_output(e)
    log_exit("Unable to import public key: %s" % output)

  # Verify that the RPM is signed.
  try:
    sig = subprocess.check_output(["rpm", "-qp", "--qf", "%{SIGPGP:pgpsig}", RPM_PATH])
    # Python3 we need to decode, Python 2 returns a string so we do nothing
    try:
      sig = sig.decode()
    except (UnicodeDecodeError, AttributeError):
      pass
    if "c6c1edb02882f26a" not in sig:
      log_exit("RPM is not signed")
  except subprocess.CalledProcessError as e:
    output = decode_output(e)
    log_exit("Error reading signature from RPM: %s" % output)

  # Verify that the signature is valid.
  try:
    subprocess.check_output(["rpm", "--checksig", RPM_PATH], stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError as e:
    output = decode_output(e)
    log_exit("RPM has invalid signature: %s" % output)


if __name__ == "__main__":
  try:
    arch = os.uname()[4]
    ver = "%s.%s.rpm" % (DEFAULT_CHRONICLE_VERSION, arch)

    parser = argparse.ArgumentParser(description="Install Chronicle")
    parser.add_argument("--latest", action="store_true", help="Install the latest version instead of the default")
    parser.add_argument("--error-exit-code", default=0, type=int, help="Exit code to return on error")
    args = parser.parse_args()
    error_exit_code = args.error_exit_code
    if args.latest:
      ver = arch

    make_dir()
    download_rpm(ver)

    try:
      verify_rpm()

      if is_audit_installed():
        remove_audit()

      install_rpm()

      log("chronicled installed")

    finally:
      os.remove(RPM_PATH)

  except Exception as e:
    log_exit("caught exception: %s" % str(e))
