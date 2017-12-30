set clipboard+=unnamed
nmap <leader>.nn :set nonu<CR>
nmap <leader>.n :set nu<CR>
"----plug tagbar---------
let g:tagbar_width=50
nmap <F8> :TagbarToggle<CR>
nmap <F9> :NERDTreeToggle<CR>

"--------go----------------
autocmd FileType go nmap <leader>gb  <Plug>(go-build)
autocmd FileType go nmap <leader>gr  <Plug>(go-run)
autocmd FileType go nmap <leader>gi  <Plug>(go-info)
autocmd FileType go nmap <leader>gm  <Plug>(go-import)
nmap <leader>gn :cnext<CR>
nmap <leader>gp :cprevious<CR>

"--------ycm--------------
"let g:ycm_filetype_blacklist = {
"      \ 'tagbar' : 1,
"      \ 'qf' : 1,
"      \ 'notes' : 1,
"      \ 'markdown' : 1,
"      \ 'unite' : 1,
"      \ 'text' : 1,
"      \ 'vimwiki' : 1,
"      \ 'pandoc' : 1,
"      \ 'infolog' : 1,
"      \ 'mail' : 1,
"      \ 'nerdtree' : 1
"      \}
"回车即选中当前项
inoremap <expr> <CR>       pumvisible() ? "\<C-y>" : "\<CR>"
let g:ycm_filetype_whitelist = { 
        \ 'go': 1,
        \ 'python':1
        \}
let g:ycm_min_num_of_chars_for_completion = 2
let g:ycm_python_binary_path = '/usr/bin/python2.7'
nnoremap <leader>jd :YcmCompleter GoTo<CR>
nnoremap <leader>ys :YcmRestartServer<CR>
