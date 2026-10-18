# Demonstration du pipe admin d'irispc : appelle daemon.status et affiche la reponse JSON.
# Aucun secret ne transite ; ce script ne verifie pas l'identite du serveur (la CLI iris le fera).
param([string]$Pipe = "iris-admin")

$client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $Pipe, [System.IO.Pipes.PipeDirection]::InOut)
$client.Connect(5000)
try {
    $json = '{"jsonrpc":"2.0","method":"daemon.status","id":1}'
    $payload = [System.Text.Encoding]::UTF8.GetBytes($json)
    $length = [BitConverter]::GetBytes([uint32]$payload.Length)
    [Array]::Reverse($length)
    $client.Write($length, 0, 4)
    $client.Write($payload, 0, $payload.Length)
    $client.Flush()

    $header = New-Object byte[] 4
    $read = 0
    while ($read -lt 4) { $n = $client.Read($header, $read, 4 - $read); if ($n -eq 0) { throw "pipe ferme" }; $read += $n }
    [Array]::Reverse($header)
    $size = [BitConverter]::ToUInt32($header, 0)
    $body = New-Object byte[] $size
    $read = 0
    while ($read -lt $size) { $n = $client.Read($body, $read, $size - $read); if ($n -eq 0) { throw "pipe ferme" }; $read += $n }
    [System.Text.Encoding]::UTF8.GetString($body)
}
finally { $client.Dispose() }
