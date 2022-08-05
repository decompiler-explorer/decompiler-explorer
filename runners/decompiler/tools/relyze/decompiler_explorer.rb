require 'relyze/core'

class Plugin < Relyze::Plugin::Analysis

    def initialize
        super( {
            :guid        => '{E15AF490-32DE-4548-8126-739DDA101FF0}',
            :name        => 'Decompiler Explorer Plugin',
            :description => 'Decompile all functions in a binary',
            :authors     => [ 'Relyze Software Limited' ],
            :license     => 'Relyze Plugin License',
            :references  => [ 'https://www.relyze.com' ],
            :options     => {
                '/in'           => nil,
                '/out'          => nil,
                '/max_threads'  => nil,
                '/func_timeout' => nil
            }
        } )
        @eol = "\n"
    end

    def run

        if( options['/in'].nil? or not ::File::exists?( options['/in'] ) )
            print_message( "Error: Pass an input file via /in" )
            return
        end

        if( options['/out'].nil? )
            print_message( "Error: Pass an output file via /out" )
            return
        end

        if( options['/max_threads'].nil? )
            require 'etc'
            options['/max_threads'] = ::Etc.nprocessors
        end

        if( options['/max_threads'].to_i <= 0 )
            print_message( "Error: /max_threads must be > 0" )
            return
        end

        func_timeout = nil

        if( not options['/func_timeout'].nil? )
            func_timeout = options['/func_timeout'].to_i
            if( func_timeout <= 0 )
                print_message( "Error: /func_timeout must be > 0 (The max number of seconds to spend decompiling a single function)" )
                return
            end
        end

        model = @relyze.analyze_file( options['/in'] )

        if( model.nil? )
            print_message( "Error: Failed to analyze '#{options['/in']}'" )
            return
        end

        work = model.functions

        pseudocode = {}

        lock = ::Mutex.new

        threads = []

        1.upto( options['/max_threads'].to_i ) do
            threads << ::Thread.new do
                begin
                    while true do

                        func = lock.synchronize do
                            work.pop
                        end

                        break if func.nil?

                        txt = "// VA=0x#{ model.rva2va( func.rva ).to_s(16) }#{@eol}"

                        begin
                            pseudo = func.to_pseudo( { :timeout => func_timeout } )
                            txt << (pseudo.nil? ? "// Failed to decompile.#{@eol}" : pseudo.gsub!("\r\n", @eol) )
                        rescue
                            txt << "// Decompilation timed out after #{func_timeout} seconds.#{@eol}"
                        end

                        lock.synchronize do
                            pseudocode[func.rva] = txt
                        end
                    end
                rescue
                    print_message( "Exception in worker thread: #{$!}" )
                end
            end
        end

        threads.each do | thread |
            thread.join
        end

        pseudocode = pseudocode.sort.to_h

        ::File.open( options['/out'], "w" ) do | f |
            pseudocode.each_value do | txt |
                f.write( txt )
                f.write( @eol )
            end
        end

    end
end
