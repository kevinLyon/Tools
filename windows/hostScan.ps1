param($ip)
if(!$ip){
    echo "Por favor digite um IP válido"
    echo "Modo de uso \.script.ps1 192.168.0.1"
} else {
    foreach ($var1 in 1..255) {
 
        try {
            $reply = ping -n 1 "$ip.$var1" | Select-String "bytes=32"
            $reply.Line.Split(' ')[2] -replace ":", "" 
        } catch {
            #Local de erro...
        }
    }
}