#!/bin/bash
# Функции
one_of_week()
{
        if [[ $((10#$CDATE)) = $((10#$WDATE)) ]]
                then
                cd $DPATH
                let "i = $i - 1"
                        if [ "$i" -lt 10 ]
                                then
                                        i=0$i
                                else
                                        i=$i
                        fi
                /bin/touch -t $(/bin/date +%y%m"$i"0000) t1
                /bin/touch -t $(/bin/date +%y%m"$i"2359) t2
                for f in $(/bin/find . -name '*' -newer t1 -and -not -newer t2 | /bin/grep -v "*.sh")
                do
                	if [ "$i" -eq 02 ]
				then
					/bin/cp $f $DPATH/month/ && echo "файл "$f" успешно скопирован в month"
				else
					/bin/cp $f $DPATH/week/ && echo "файл "$f" успешно скопирован в week"
			fi
                done
        fi

}

create_dir()
{
	cd $DPATH
	for var in week month year
	do
		if [ -d $var ]
			then
				echo "папка "$var" существует"
			else
				/bin/mkdir $var && echo "папка "$var" создана"
		fi
	done
}
#
# Вывод
exec 1> sc_b_log.txt
# Задание переменных
# Скрипт выполняется из папки, где он лежит
DPATH=$(cd `dirname $0` && pwd) && echo "текущая директория" $DPATH
#Проверка существования папок
create_dir
# Текущая дата
CDATE=$(/bin/date +%d%m%y)
# Контрольная дата "год"
YDATE=$(/bin/date +0301%y)
# Контрольная дата "неделя" и "месяц"
for i in 03 10 17 24
	do
	WDATE=$(/bin/date +$i%m%y)
	one_of_week
done
#
if [[ $((10#$CDATE)) = $((10#$YDATE)) ]] # Проверка совпадения даты для копирования "год"
# Если есть совпадение, то нахождение файлов за 2 января текущего года и копирование их в папку year
then
        cd $DPATH
    touch -t $(/bin/date +%y01020000) y1
    touch -t $(/bin/date +%y01022359) y2
    for f in $(/bin/find . -name '*' -newer y1 -and -not -newer y2 | /bin/grep -v "*.sh")
    do
    /bin/cp $f $DPATH/year/ && echo "файл "$f" успешно скопирован в year"
    done
fi
#
cd $DPATH
find $DPATH -maxdepth 1 -type f -mtime +7 | /bin/grep -v ".sh" | xargs rm -f # "Удаление файлов старше 7-ми дней из корневой папки"
find $DPATH/week -maxdepth 1 -type f -mtime +30 | /bin/grep -v ".sh" | xargs rm -f # "Очистка папки week, от файлов старше 1 месяца"
find $DPATH/month -maxdepth 1 -type f -mtime +365 | /bin/grep -v ".sh" | xargs rm -f # "Очистка папки month от фалйов старше года"
