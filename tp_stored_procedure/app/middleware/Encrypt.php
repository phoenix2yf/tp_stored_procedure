<?php
declare (strict_types = 1);

namespace app\middleware;

use think\Response;

class Encrypt
{
    /**
     * 处理请求
     *
     * @param \think\Request $request
     * @param \Closure       $next
     * @return Response
     */
    public function handle($request, \Closure $next)
    {
        $response = $next($request);
        $content = $response->getContent();
        $content = json_decode($content, true);
        $data = $content['data'] ?? [];
        if (!empty($data)) {
            // 添加中间件执行代码
            $mini_secret = 'lfKARxycJnB0iIiy0l3/iA==';
            $mini_iv = 'azxGaqxq/BSTTXEjj0/87w==';
            $str = json_encode($data);
            $mini_sign = openssl_encrypt($str, 'AES-128-CBC', $mini_secret, 0, $mini_iv);
            $content['data'] = ['result' => $mini_sign];
            $response->content(json_encode($content));
        }
    }
}
