program devault;
uses
  math, sysutils, strutils, getopts, DCPcrypt2, DCPsha256, DCPrijndael, kdf;

function unhexlify(s:AnsiString):AnsiString;
var i:integer;
    tmpstr:AnsiString;
begin
  tmpstr:='';
  for i:=0 to (length(s) div 2)-1 do
    tmpstr:=tmpstr+char(Hex2Dec(Copy(s,i*2+1,2)));
  unhexlify:=tmpstr;
end;

function hexlify(s:AnsiString):AnsiString;
var i:integer;
    tmpstr:AnsiString;
begin
  tmpstr:='';
  for i:=1 to (length(s)) do
    tmpstr:=tmpstr+IntToHex(ord(s[i]),2);
  hexlify:=tmpstr;
end;

procedure showbanner();
begin
  WriteLn(stderr, 'DeVault v1.0');
  Writeln(stderr, '(C) 2021, Sergey Pechenko. All rights reserved');
  Writeln(stderr, 'Run with "-l" option to see license');
end;

procedure showlicense();
begin
  WriteLn(stderr,'Redistribution and use in source and binary forms, with or without modification,');
  WriteLn(stderr,'are permitted provided that the following conditions are met:');
  WriteLn(stderr,'* Redistributions of source code must retain the above copyright notice, this');
  WriteLn(stderr,'   list of conditions and the following disclaimer;');
  WriteLn(stderr,'* Redistributions in binary form must reproduce the above copyright notice, ');
  WriteLn(stderr,'   this list of conditions and the following disclaimer in the documentation');
  WriteLn(stderr,'   and/or other materials provided with the distribution.');
  WriteLn(stderr,'* Sergey Pechenko''s name may not be used to endorse or promote products');
  WriteLn(stderr,'   derived from this software without specific prior written permission.');
  WriteLn(stderr,'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"');
  WriteLn(stderr,'AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,');
  WriteLn(stderr,'THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE');
  WriteLn(stderr,'ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE');
  WriteLn(stderr,'FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES');
  WriteLn(stderr,'(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;');
  WriteLn(stderr,'LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON');
  WriteLn(stderr,'ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT');
  WriteLn(stderr,'(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,');
  WriteLn(stderr,'EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.');
  WriteLn(stderr,'Commercial license can be obtained from author');
end;

procedure showhelp();
begin
  WriteLn(stderr,'Usage:');
  WriteLn(stderr,Format('%s <-p password | -w vault_password_file> [-f secret_file]',[ParamStr(0)]));
  WriteLn(stderr,#09'"password" is a text string which was used to encrypt your secured content');
  WriteLn(stderr,#09'"vault_password_file" is a file with password');
  WriteLn(stderr,#09'"secret_file" is a file with encrypted content');
  WriteLn(stderr,'When "-f" argument is absent, stdin is read by default');
end;

var secretfile, passwordfile, pass, salt, b_derived_key, b_key1, b_key2, b_iv,
    hmac_new, cphrtxt, fullfile, header, tmpstr, hmac:Ansistring;
    Cipher: TDCP_rijndael;
    data: RawByteString;
    fulllist: TStringArray;
    F: Text;
    c: char;
    opt_idx: LongInt;
    options: array of TOption;
const KEYLENGTH=32; // for AES256
const IV_LENGTH=128 div 8;
const CONST_HEADER='$ANSIBLE_VAULT;1.1;AES256';

procedure preparecliparams();
begin
  SetLength(options, 6);
  with options[1] do
    begin
      name:='password';
      has_arg:=Required_Argument;
      flag:=nil;
      value:=#0;
    end;
  with options[2] do
    begin
      name:='file';
      has_arg:=Required_Argument;
      flag:=nil;
      value:=#0;
    end;
  with options[3] do
    begin
      name:='passwordfile';
      has_arg:=Required_Argument;
      flag:=nil;
      value:=#0;
    end;
  with options[4] do
    begin
      name:='version';
      has_arg:=No_Argument;
      flag:=nil;
      value:=#0;
    end;
  with options[5] do
    begin
      name:='license';
      has_arg:=No_Argument;
      flag:=nil;
      value:=#0;
    end;
  with options[6] do
    begin
      name:='help';
      has_arg:=No_Argument;
      flag:=nil;
      value:=#0;
    end;
end;

begin
  repeat
    c:=getlongopts('p:f:w:lh?',@options[1],opt_idx);
    case c of
      'h','?' : begin showhelp(); halt(0); end;
      'p' : pass:=optarg;
      'f' : secretfile:=optarg;
      'w' : passwordfile:=optarg;
      'v' : begin showbanner(); halt(0); end;
      'l' : begin showlicense(); halt(0); end;
      ':' : writeln ('Error with opt : ',optopt); // not a mistake - defined in getops unit
     end;
  until c=endofoptions;
  if pass = '' then // option -p not set
    if passwordfile <> '' then
      try
        Assign(F,passwordfile);
        Reset(F);
        Readln(F,pass);
        Close(F);
      except
        on E: EInOutError do
        begin
          Close(F);
          writeln(stderr, 'Password not set and password file cannot be read, exiting');
          halt(1);
        end;
      end
    else
      begin // options -p and -w are both not set
          writeln(stderr, 'Password not set, password file not set, exiting');
          showhelp();
          halt(1);
      end;
  try
    Assign(F,secretfile);
    Reset(F);
  except 
    on E: EInOutError do
    begin
      writeln(stderr, Format('File %s not found, exiting',[secretfile]));
      halt(1);
    end;
  end;
  readln(F,header);
  if header<>CONST_HEADER then
    begin
      writeln(stderr, 'Header mismatch');
      halt(1);
    end;
  fullfile:='';
  while not EOF(F) do
    begin
    Readln(F,tmpstr);
    fullfile:=fullfile+tmpstr;
    end;
  Close(F);
  fulllist:=unhexlify(fullfile).Split([#10],3);
  salt:=fulllist[0];
  hmac:=fulllist[1];
  cphrtxt:=fulllist[2];
  salt:=unhexlify(salt);
  cphrtxt:=unhexlify(cphrtxt);
  b_derived_key:=PBKDF2(pass, salt, 10000, 2*32+16, TDCP_sha256);
  b_key1:=Copy(b_derived_key,1,KEYLENGTH);
  b_key2:=Copy(b_derived_key,KEYLENGTH+1,KEYLENGTH);
  b_iv:=Copy(b_derived_key,KEYLENGTH*2+1,IV_LENGTH);
  hmac_new:=lowercase(hexlify(CalcHMAC(cphrtxt, b_key2, TDCP_sha256)));
  if hmac_new<>hmac then
    begin
    writeln(stderr, 'Digest mismatch - file has been tampered with, or an error has occured');
    Halt(1);
    end;
  SetLength(data, Length(cphrtxt));
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(b_key1[1], 256, @b_iv[1]);
    Cipher.DecryptCTR(cphrtxt[1], data[1], Length(data));
    Cipher.Burn;
  finally
    Cipher.Free;
  end;
  Writeln(data);
end.
