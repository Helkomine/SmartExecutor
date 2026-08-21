# VM

## Ý tưởng

Máy ảo này dựa trên ý tưởng của các máy ảo như Universal Router hay Weiroll, nó được bổ sung thêm khả năng xử lý callback, reentrancy và branch ngay trong lõi hợp đồng.

Nó được thiết kế để tương thích với tài khoản thông minh, trong đó có hai cách tiếp cận: 

- Hoạt động như một hợp đồng bên ngoài (tương tự Universal Router) để giữ tương thích với các tài khoản thông minh hiện có và giảm bề mặt tấn công. 
- Tích hợp trực tiếp như một phần trong mã tài khoản, điều này giúp tài khoản linh hoạt hơn trong thực thi, ví dụ nó có thể gọi hợp đồng pool và xử lý trực tiếp callback nhận được thay vì phải phê duyệt token và gọi execute trên hợp đồng router bên ngoài, ngoài ra nó cũng có thể dùng để thực hiện các khoản vay nhanh mà không cần viết thêm hợp đồng ngoài.

Thiết kế ban đầu giả định rằng khả năng giao dịch thông minh được thêm vào trong tài khoản thông minh, do đó các tiêu chuẩn an toàn được thiết kế khắt khe hơn, chẳng hạn các quy tắc phức tạp trong xử lý callback.

Hai cách tiếp cận trên giống nhau về chức năng lõi nhưng có sự khác biệt về quan điểm kiểm soát an toàn.

- Hợp đồng ngoài về lý thuyết không cần trang bị cơ chế an toàn nào, tuy nhiên những vấn đề phát sinh như reentrancy và nắm giữ phê duyệt ERC20 hay ERC721 bền vững trên hợp đồng đang tạo ra rủi ro cho những người đã từng tương tác với hợp đồng này. Tuy nhiên nếu siết chặt điều kiện quá mức sẽ làm mất đi một số khả năng có giá trị, điển hình là truy vấn theo lô, vì về mặt kỹ thuật các cơ chế an toàn sử dụng bộ nhớ tạm thời, mà lệnh ghi vào bộ nhớ này (TSTORE) làm thay đổi trạng thái và khiến STATICCALL thất bại khi gọi. Ngoài ra khả năng kiểm soát bộ chọn cũng là vấn đề, nếu ta chỉ chặn một số bộ chọn như ERC20.transferFrom thì ta không thể chắc chắn rằng các bộ chọn khác là an toàn (vì ta không có tiêu chuẩn xác định bộ chọn nào là an toàn để gọi). Xem xét các hợp đồng đã tồn tại trên mạng như Multicall không có cơ chế kiểm soát bộ chọn, vậy hướng thiết kế dự kiến chỉ bao gồm tối thiểu chức năng kháng reentrancy cho hợp đồng ngoài.
- Tài khoản thông minh cần cơ chế an toàn đáng kể, một lời gọi thông qua điểm vào tài khoản (ví dụ execute(...)) nhìn chung là an toàn vì nó chịu các cơ chế kiểm soát truy cập tài khoản hiện có (ví dụ thông qua chữ ký), tuy nhiên cơ chế xử lý callback là một vấn đề mới phải được xem xét vì hiện tại ta chưa có một tiêu chuẩn ổn định nào xác định cho thiết kế này. Tuy nhiên tác giả cho rằng chức năng này rất đáng giá, vì nó mở khóa những khả năng siêu phàm mà hiện nay chỉ hợp đồng mới làm được, ví dụ flash loan rất khó để thực hiện trực tiếp mà không có hợp đồng xử lý đặc biệt, vì tài khoản cần tiếp nhận callback và giải quyết chúng, đối với một router cố định thì việc xử lý các dữ liệu callback tùy ý này rất khó khăn (thường thì router chỉ nhận các data callback cố định và thực hiện các hành động xác định như hoàn trả token bán).

Ta sẽ tiếp cận thiết kế bắt đầu từ hợp đồng ngoài cho đến tài khoản thông minh.

## Việc thực thi trên calldata

Để đơn giản hóa quy trình, giảm chi phí và hạn chế xung đột bộ nhớ, chỉ calldata được chọn để làm vùng chứa thực thi chính thức, tất cả các vùng có liên quan bao gồm memory và transient storage chỉ đóng vai trò phụ trợ, chúng được dùng để ghi nhớ tạm thời dữ liệu nhằm phục vụ cho việc xử lý dữ liệu
## Giải quyết callback / reentrancy

Callback là một trường hợp đặc biệt của reentrancy khi nó chủ ý mời gọi hợp đồng tái nhập vào nó. Điều này cũng phát sinh những rủi ro ngoài ý muốn, loại rủi ro này chỉ xuất hiện trong thời gian chạy hợp đồng, vì kẻ tấn công không thể làm gì nếu tài khoản chưa được mở khóa, tuy nhiên việc mở khóa không đúng cách vô tình để lọt khe hở tiếp cận tài khoản trong thời gian chạy và cho phép kẻ tấn công nhúng các chương trình độc hại khiến tài khoản bị thay đổi hành vi vĩnh viễn.

Hướng thiết kế ban đầu chỉ dựa trên ghi chú địa chỉ tái nhập trước khi gọi ra bên ngoài, sau khi tài khoản nhận được lời gọi sẽ tiến hành kiểm tra người gọi đã được đánh dấu (thường trên bộ nhớ tạm thời EIP1153) để xác nhận hợp lệ. Tuy nhiên người gọi độc hại có thể truyền vào các dữ liệu độc hại ngoài ý muốn để tấn công, kiểu tấn công này thông thường không gây ra nhiều vấn đề nếu bên gửi callback được kiểm chứng là an toàn, tuy nhiên trong các cuộc tấn công thao túng trên giao diện có thể cài đặt một người gửi callback độc hại trong calldata mà người dùng không hề hay biết, dữ liệu này trông có vẻ an toàn nhưng khi ký vào để thực thi thì khi hợp đồng đó gửi callback nó sẽ truyền đi một calldata độc hại vào tài khoản.

Do vậy một tài khoản cần kiểm tra cả dữ liệu đầu vào callback có hợp lệ không. Nhưng ta cần xác định rõ tiêu chí an toàn, dữ liệu callback luôn bao gồm phần siêu dữ liệu (như chữ ký hàm, đối số thông tin khác) do đó nó cần được loại bỏ khi được đánh giá, mặc dù phần siêu dữ liệu đôi khi cũng mang theo thông tin cần thiết (ví dụ số dư token cần trả) tuy nhiên nó có thể là giá trị động nên gần như không thể kiểm soát, đề xuất là kiểm soát kích thước calldata, một hợp đồng gửi callback tốt nên có kích thước calldata có thể xác định được trong thời gian chạy và không nên phụ thuộc vào môi trường. Sau khi loại bỏ phần siêu dữ liệu, ta giữ lại phần data callback quan trọng, phần này được đối chiếu dựa trên băm dữ liệu được lưu trên bộ nhớ tạm thời đã được thiết lập trước đó. Việc thiết lập dữ liệu này cũng có cùng phương pháp với handle callback, trong đó chỉ một phần dữ liệu là callback, phần còn lại là siêu dữ liệu, do đó chỉ phần dữ liệu dự kiến dùng cho callback mới được hash trước khi chuyển tiếp. Một vấn đề nhỏ cần xem xét là thiết kế này cũng ngầm giả định rằng chỉ có một payload callback duy nhất được chuyển tiếp, tức là nếu một hợp đồng cố gắng chuyển tiếp callback gồm nhiều payload (ví dụ bytes, bytes, ...) thì tài khoản nhận được sẽ không thể xử lý trực tiếp, tuy nhiên nó vẫn có thể ủy thác các payload này cho một lệnh gọi con trên chính nó. Tóm lại tài khoản phải kiểm tra kích thước calldata và payload callback được gửi đến.

Thêm một thiết kế nữa là việc thực thi calldata nên xác định, tức là khi ta đã chọn vùng nào để làm chương trình thực thi thì nó chỉ chạy trong vùng đó cho đến hết khung gọi hàm, tuy nhiên việc đọc tùy ý trên calldata vẫn được giữ lại vì lý do như đã được nêu trên.

Ngay cả như vậy thì tài khoản vẫn chưa thể chắc chắn rằng tái nhập không diễn ra, vì tài khoản còn giữ băm hợp lệ, một hợp đồng độc hại có thể gọi lại nhiều lần trên tài khoản này (thao tác Multicall) để lợi dụng thời gian mà băm này còn hoạt động để phát lại thao tác callback trước đó. Đề xuất bổ sung thêm một số nonce, giá trị này tăng một mỗi khi thực thi callback thành công (ta có thể xem nó như một giao dịch nhỏ), tuy nhiên tên gọi này có thể gây nhầm lẫn với nonce được dùng trong ký tài khoản nên nó được đổi tên thành continuation.

Để tăng tính an toàn, việc kiểm tra nên bao gồm độ sâu cuộc gọi (một giá trị nội bộ trong hợp đồng).

Như vậy mã băm callback được cấu tạo bởi các thành phần sau đây:

`callbackHash = keccak256(abi.encode(callbackSender, calldatasize(), ++depth, continuation, keccak256(payload)))`.

Ở đây độ sâu cuộc gọi được mặc định tăng một vì ta dự kiến rằng tài khoản sẽ nhận được callback mà không có thêm lệnh gọi phụ xen giữa nào nữa, depth tùy chỉnh là không cần thiết.

### Fallback

Trong Solidity, tài khoản phải cài đặt fallback() để có thể xử lý callback và có thể thêm receive() vì trình biên dịch có thể đưa ra cảnh báo thiếu hàm receive() khi triển khai hợp đồng chỉ bao gồm fallback() và các hàm có bộ chọn xác định. Tuy nhiên có thể phát sinh xung đột nếu tài khoản đang có cấu hình riêng cho fallback(), khi đó ta cần phân tách hợp lý ranh giới cấu hình khác với callback, chẳng hạn nếu là mô hình kim cương, khi đó với mỗi ánh xạ bộ chọn bằng address(0) thì thay vì hoàn tác nó phải chuyển tiếp tới callback.

### Thay đổi cấu hình tài khoản

Vì callback cho phép việc truy cập đầy đủ vào chức năng của một tài khoản, một số hạn chế được đặt ra để đảm bảo an toàn. Trong đó việc thay đổi cấu hình tài khoản bị cấm trong thời gian callback.

## Minimal Register

Như được mô tả ở trên, callback mà tài khoản nhận được
