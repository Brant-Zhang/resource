let g:tagbar_width=30
map <F6> :TagbarToggle<CR>
map <F7> :NERDTreeToggle<CR>
let g:go_highlight_types = 1
let g:go_highlight_functions = 1
let g:go_highlight_methods = 1
let g:go_highlight_fields = 1
let g:go_highlight_operators = 1
let g:go_highlight_build_constraints = 1

let g:ycm_python_binary_path = '/usr/bin/python3'
nnoremap <leader>jd :YcmCompleter GoTo<CR>

