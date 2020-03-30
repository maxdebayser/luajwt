local b64 = nil
local unb64 = nil
local http = nil
if ngx ~= nil then
  b64 = ngx.encode_base64
  unb64 = ngx.decode_base64
  http = require "resty.http"
else
  local base64 = require 'base64'
  b64 = base64.encode
  unb64 = base64.decode
end
local cjson  = require'cjson'
local digest = require 'openssl.digest'
local pkey   = require 'openssl.pkey'
local x509   = require 'openssl.x509'
local hmac   = require 'openssl.hmac'

function safe_require(mod)
  local status, loadedMod = pcall(function() return require(mod) end)
  if status then
    return loadedMod
  else
    return status, loadedMod
  end
end

local config = safe_require "config"

if not config then
  config = {
     ssl_verify = true
  }
end

local bit = safe_require'bit'

local digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' }

local tohex = nil

if bit then
  local bit_tohex = bit and bit.tohex or nil
  --fastest in luajit
  tohex = function(s)
    local result = {}
    for i = 1, #s do
      local byte = string.byte(s, i)
      table.insert(result, digits[bit.rshift(byte, 4) + 1])
      table.insert(result, digits[bit.band(byte, 15)+ 1])
    end
    return table.concat(result)
  end
elseif _VERSION == 'Lua 5.3' then
  --fastest in lua 5.3
  --compile dynamically to be syntactically compatible with 5.1
  loader, err = load[[
    local digits = ...
    return function(s)
      local result = ""
      for i = 1, #s do
        local byte = string.byte(s, i)
        result = result..(digits[(byte >> 4) + 1])..(digits[(byte&15)+ 1])
      end
      return result
    end
  ]]
  tohex = loader(digits)
else
  --fastest in lua 5.1
  tohex = function(s)
    local result = ""
    for i = 1, #s do
      local byte = string.byte(s, i)
      result = result..(digits[math.floor(byte / 16) + 1])..(digits[(byte % 16) + 1])
    end
    return result
  end
end

local function signRS(data, key, algo)
    local ok, result = pcall(function()
      if type(key) == 'string' then
        key = pkey.new(key)
      end
      return key:sign(digest.new(algo):update(data))
    end)
    if not ok then return nil, result end
    return result
end

local function verifyRS(data, signature, key, algo)
    local ok, result = pcall(function()
      if type(key) == 'string' then
        key = pkey.new(key)
      end
      return key:verify(signature, digest.new(algo):update(data))
    end)
    if not ok then return nil, result end
    return result
end

local alg_sign = {
	['HS256'] = function(data, key) return tohex(hmac.new(key, 'sha256'):final (data)) end,
	['HS384'] = function(data, key) return tohex(hmac.new(key, 'sha384'):final (data)) end,
	['HS512'] = function(data, key) return tohex(hmac.new(key, 'sha512'):final (data)) end,
	['RS256'] = function(data, key) return signRS(data, key, 'sha256') end,
	['RS384'] = function(data, key) return signRS(data, key, 'sha384') end,
	['RS512'] = function(data, key) return signRS(data, key, 'sha512') end
}

local alg_verify = {
	['HS256'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha256'):final (data)) end,
	['HS384'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha384'):final (data)) end,
	['HS512'] = function(data, signature, key) return signature == tohex(hmac.new (key, 'sha512'):final (data)) end,
	['RS256'] = function(data, signature, key) return verifyRS(data, signature, key, 'sha256') end,
	['RS384'] = function(data, signature, key) return verifyRS(data, signature, key, 'sha384') end,
	['RS512'] = function(data, signature, key) return verifyRS(data, signature, key, 'sha512') end
}

local function b64_url_encode(input)
	local result = b64(input)

	result = result:gsub('+','-'):gsub('/','_'):gsub('=','')

	return result
end

local function b64_url_decode(input)
--	input = input:gsub('\n', ''):gsub(' ', '')

	local reminder = #input % 4

	if reminder > 0 then
		local padlen = 4 - reminder
		input = input .. string.rep('=', padlen)
	end

	input = input:gsub('-','+'):gsub('_','/')

	return unb64(input)
end

local function tokenize(str, div, len)
	local result, pos = {}, 0

	for st, sp in function() return str:find(div, pos, true) end do

		result[#result + 1] = str:sub(pos, st-1)
		pos = sp + 1

		len = len - 1

		if len <= 1 then
			break
		end
	end

	result[#result + 1] = str:sub(pos)

	return result
end

local M = {}

function M.encode(data, key, alg)
	if type(data) ~= 'table' then return nil, "Argument #1 must be table" end
	if type(key) ~= 'string' then return nil, "Argument #2 must be string" end

	alg = alg or "HS256"

	if not alg_sign[alg] then
		return nil, "Algorithm not supported"
	end

	local header = { typ='JWT', alg=alg }

	local segments = {
		b64_url_encode(cjson.encode(header)),
		b64_url_encode(cjson.encode(data))
	}

	local signing_input = table.concat(segments, ".")
	local signature, error = alg_sign[alg](signing_input, key)
	if signature == nil then
		return nil, error
	end

	segments[#segments+1] = b64_url_encode(signature)

	return table.concat(segments, ".")
end

function M.decode(data, key, verify) 
    local keyset = { default=key } 
    return M.decode_keyset(data,keyset,verify)
end

function M.decode_keyset(data, keyset, verify)
	if keyset and verify == nil then verify = true end
	if type(data) ~= 'string' then return nil, "Argument #1 must be string" end
	if verify and type(keyset) ~= 'table' then return nil, "Argument #2 must be table" end

	local token = tokenize(data, '.', 3)

	if #token ~= 3 then
		return nil, "Invalid token"
	end

	local headerb64, bodyb64, sigb64 = token[1], token[2], token[3]

	local ok, header, body, sig = pcall(function ()
		return	cjson.decode(b64_url_decode(headerb64)),
			cjson.decode(b64_url_decode(bodyb64)),
			b64_url_decode(sigb64)
	end)

	if not ok then
		return nil, "Invalid json"
	end

	if verify then

		if not header.typ or (header.typ ~= "JOSE" and header.typ ~= "JWT") then
			return nil, "Invalid typ"
		end

		if not header.alg or type(header.alg) ~= "string" then
			return nil, "Invalid alg"
		end

		if body.exp and type(body.exp) ~= "number" then
			return nil, "exp must be number"
		end

		if body.nbf and type(body.nbf) ~= "number" then
			return nil, "nbf must be number"
		end

		if not alg_verify[header.alg] then
			return nil, "Algorithm not supported"
		end
        
        local kid = header.kid

        local key = keyset[kid] or keyset["default"]

        if key == nil then
			return nil, "no key could be found to validate the token"
        end

		local verify_result, error
			= alg_verify[header.alg](headerb64 .. "." .. bodyb64, sig, key);

		if verify_result == nil then
			return nil, error
		elseif verify_result == false then
			return nil, "Invalid signature"
		end

		if body.exp and os.time() >= body.exp then
			return nil, "Not acceptable by exp"
		end

		if body.nbf and os.time() < body.nbf then
			return nil, "Not acceptable by nbf"
		end
	end

	return body
end

-- Beginning of code adapted from https://github.com/zmartzone/lua-resty-openidc
-- released under the APACHE license, see license terms and authors in the
-- licenses/lua-resty-openidc/ directory

local function split_by_chunk(text, chunkSize)
  local s = {}
  for i = 1, #text, chunkSize do
    s[#s + 1] = text:sub(i, i + chunkSize - 1)
  end
  return s
end

local wrap = ('.'):rep(64)

local envelope = "-----BEGIN %s-----\n%s\n-----END %s-----\n"

local function der2pem(data, typ)
  typ = typ:upper() or "CERTIFICATE"
  data = b64(data)
  return string.format(envelope, typ, data:gsub(wrap, '%0\n', (#data - 1) / 64), typ)
end


local function encode_length(length)
  if length < 0x80 then
    return string.char(length)
  elseif length < 0x100 then
    return string.char(0x81, length)
  elseif length < 0x10000 then
    return string.char(0x82, math.floor(length / 0x100), length % 0x100)
  end
  error("Can't encode lengths over 65535")
end


local function encode_sequence(array, of)
  local encoded_array = array
  if of then
    encoded_array = {}
    for i = 1, #array do
      encoded_array[i] = of(array[i])
    end
  end
  encoded_array = table.concat(encoded_array)

  return string.char(0x30) .. encode_length(#encoded_array) .. encoded_array
end

local function encode_binary_integer(bytes)
  if bytes:byte(1) > 127 then
    -- We currenly only use this for unsigned integers,
    -- however since the high bit is set here, it would look
    -- like a negative signed int, so prefix with zeroes
    bytes = "\0" .. bytes
  end
  return "\2" .. encode_length(#bytes) .. bytes
end

local function encode_sequence_of_integer(array)
  return encode_sequence(array, encode_binary_integer)
end

local function encode_bit_string(array)
  local s = "\0" .. array -- first octet holds the number of unused bits
  return "\3" .. encode_length(#s) .. s
end

local function openidc_pem_from_x5c(x5c)
  -- TODO check x5c length
  print("Found x5c, getting PEM public key from x5c entry of json public key")
  local chunks = split_by_chunk(b64(b64_url_decode(x5c[1])), 64)
  local pem = "-----BEGIN CERTIFICATE-----\n" ..
      table.concat(chunks, "\n") ..
      "\n-----END CERTIFICATE-----"
  print("Generated PEM key from x5c:", pem)
  return pem
end

local function openidc_pem_from_rsa_n_and_e(n, e)
  print("getting PEM public key from n and e parameters of json public key")

  local der_key = {
    b64_url_decode(n), b64_url_decode(e)
  }
  local encoded_key = encode_sequence_of_integer(der_key)
  local pem = der2pem(encode_sequence({
    encode_sequence({
      "\6\9\42\134\72\134\247\13\1\1\1" -- OID :rsaEncryption
          .. "\5\0" -- ASN.1 NULL of length 0
    }),
    encode_bit_string(encoded_key)
  }), "PUBLIC KEY")
  print("Generated pem key from n and e: ", pem)
  return pem
end

function M.public_key_from_jwk(jwk)
  local pem
  -- TODO check x5c length
  if jwk.x5c then
    pem = x509.new(openidc_pem_from_x5c(jwk.x5c)):getPublicKey()
  elseif jwk.kty == "RSA" and jwk.n and jwk.e then
    pem = pkey.new(openidc_pem_from_rsa_n_and_e(jwk.n, jwk.e))
  else
    return nil, "don't know how to create RSA key/cert for " .. cjson.encode(jwk)
  end

  return pem
end

-- END of adapted code
--

function M.public_keys_from_jwks(jwks)
    local ret = {}
    for _,entry in ipairs(jwks.keys) do
       ret[entry.kid] = M.public_key_from_jwk(entry)
    end
    return ret
end

function M.get_jwks_from_authentication_server(host)
  local httpc = http.new()
  local res, err = httpc:request_uri(host, {
    method = "GET",
    headers = {
      ["Accept"] = "application/json"
    },
    keepalive_timeout = 60,
    keepalive_pool = 10,
    ssl_verify=config.ssl_verify
  })
  
  if res and 200 <= res.status and res.status < 300 then
     return cjson.decode(res.body) 
  else
     ngx.log(ngx.ERR, err)
  end
  return nil, err
end

function M.get_public_keys_from_authentication_server(host)
    local jwks,err = M.get_jwks_from_authentication_server(host)
    if jwks ~= nil then
        return M.public_keys_from_jwks(jwks)
    end
    return nil,err
end

return M
