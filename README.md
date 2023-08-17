# idenLib-for-IDA
idenLib database and idenLib.py for IDA

# HDSD (đọc kỹ trước khi dùng)
Thông tin và hướng dẫn về idenLib các bạn nên tham khảo, đọc kỹ ở github của tác giả:
https://github.com/secrary/idenLib
Mình nói sơ lại, bộ idenLib gồm các thành phần sau:
1. exe chính là idenlib.exe, dùng để tạo file .sig theo format của riêng nó. Nó chỉ support COFF .lib/.obj của Windows (MS), I386 và AMD64.
Exe này dùng Zydis disassemly engine để get opcodes của từng hàm trong file .lib/.obj, nối thành các chuổi hex opcodes và lưu lại thành buffer text lines.
Sau đó nó dùng Zstd để compress buffer này thành 1 file zip theo Zstd format, đuôi là .sig hay .sig64 theo .lib/.obj là I386 hay AMD64, vào 2 thư mục tương ứng là x86/x64. 
Các bạn có thể dùng 7zip để xem file .sig/.sig64 này.
2. 2 plugin cho x64dbg, 32bit và 64bit, sẽ đọc thư mục SymEx (cùng cấp với x32dbg.exe/x64dbg.exe),  lấy hết tất cả các file .sig/.sig64 theo 32 hay 64bit ở cấp ngoài,  để scan và apply sig vào cho các hàm của file ta đang debug.
3. idenLib.py của tác giả, hơi khó dùng.
File này tôi đã mod lại nhiều, cách sử dụng bên ngoài thì giống với idenLib.py của tác giả, nhưng lưu cache vào cùng thư mục SymEx, không lưu vào %LOCALAPPDATA%, cho phép chọn multifile sigs và dùng lại cached sigs hay chọn new mới.
4. Thư mục SymEx chứa các file .sig/.sig64 tôi đã tạo từ các .lib/.obj tôi đang có trên máy, gồm cả Visual Studio 2019 v16.x và Windows Kits (Windows SDK)

# HD cài đặt:
1. Chép idenLib.py vào thư mục IDA\plugins của bạn
2. Chép hết thư mục SymEx vào IDA user dir, trên Windows thì ở %AppData%\HexRays\IDA... hay trong biến môi trường IDAUSR mà các bạn đã set.
Vd máy tôi là IDAUSR=Z:\IDA\usrdir.
Cái gì không phải từ bộ cài gốc của IDA, tôi tống vào đây hết. Sau này cần chép đi đâu, chép thư mục này thôi là đủ.
3. Install zstd: pip install zstd
4. Install Capstone của anh Quỳnh: pip install capstone. 

Xong

5. Sau khi mở, IDA, load file xong, vào Edit, sẽ có menu idenLib, trong đó có 3 menu item con.... 
- Cái đầu là scan và apply sigs đã cache. Chưa cache thì chọn mới.
- Cái kế là chọn sig mới để tạo cache
- Cái 3 là about của tác giả.

Hết. 

Các bạn cứ thử mò, vọc đi sẽ biết cách dùng ngay, viết dài mệt quá :D

idenLib do thuật toán quét theo opcodes nên tỷ lệ nhận diện các hàm không cao, nó cũng từa tựa như FLIRT của IDA. Các bạn có thể xem nó như 1 bổ sung cho .sig của IDA.
Nếu các bạn có tạo file .sig/.sig64 mới, có thể gởi cho tôi file đã tạo hay file .lib/.obj các bạn cần tạo, tôi sẽ update vào bộ SymEx này.
Quan trọng là khi apply sig, các bạn cần xác định file các bạn đang phân tích đã được build với compiler gì, ver gì, dùng các lib nào của compiler và 3rd libs màp...
Vd nhiều mèo trước giờ dùng CryptoPP (Crypto++), Miracl... Cobalt Strike Beacon thì dùng LibTomCrypt/LibTomMath...

Không hiểu gì thì chịu khó xem code trong file .py. Bug thì quăng lên đây chửi xối xả cho tui fix :D (code như con két...)

Chân chọng, bét xì ga :D

HTC
